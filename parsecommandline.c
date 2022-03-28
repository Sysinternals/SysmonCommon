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
// ParseCommandLine.c
//
// Implements command line parsing
//
//====================================================================
#include "stdafx.h"
#include "rules.h"
#include "sysmonevents.h"
#include "xml.h"
#include <libxml/parser.h>
#include <sys/types.h>
#include <string.h>
#include "printfFormat.h"

#if defined __linux__
#include <sys/ioctl.h>
#include <unistd.h>
#define DEFAULT_CRYPTO          ALGO_SHA256
volatile LONG g_algorithm = DEFAULT_CRYPTO;
ULONG
SysmonCryptoCurrent(
        VOID
        )
{
        return (ULONG)*(volatile LONG*)&g_algorithm;
}
#endif

#define NO_MAX_LENGTH (-1)
int g_VariableFieldSizes[SYSMON_MAX_EVENT_ID][SYSMON_MAX_EVENT_Fields];

//--------------------------------------------------------------------
//
// LoadVariableFieldSizes
//
// Initialize and load any user-specified max field sizes
//
//--------------------------------------------------------------------
BOOLEAN LoadVariableFieldSizes(PCTSTR constFieldSizeStr)
{
    PTCHAR numPtr = NULL;
    unsigned int i = 0, j = 0;
    PTCHAR entry = NULL;
    PTCHAR entrySave = NULL;
    int value = 0;
    PTCHAR fieldSizeStr = NULL;
    BOOLEAN found = FALSE;
    size_t strLen = 0;

    //
    // Inititalise all entries to -1 (NO_MAX_LENGTH) to indicate no max size set
    //
    memset( g_VariableFieldSizes, NO_MAX_LENGTH, sizeof( g_VariableFieldSizes ) );

    //
    // If no FieldSizes entry, nothing to do
    //
    if( constFieldSizeStr == NULL || *constFieldSizeStr == 0x00)
    {

        return TRUE;
    }

    //
    // Check for illegal characters
    //
    strLen = _tcslen( constFieldSizeStr );
    for( i = 0; i < strLen; i++ ) {
        if( !_istalnum( constFieldSizeStr[i] ) && constFieldSizeStr[i] != _T(',') && constFieldSizeStr[i] != _T(':') ) {
            _tprintf( _T("FieldSizes option ('%s') has invalid character: '%c'.\n"), constFieldSizeStr, constFieldSizeStr[i] );
            return FALSE;
        }
    }

    //
    // Duplicate string so we can modify it
    //
    fieldSizeStr = malloc( (_tcslen( constFieldSizeStr ) + 1) * sizeof( TCHAR ) );
    if( fieldSizeStr == NULL ) {

        return FALSE;
    }

    _tcscpy( fieldSizeStr, constFieldSizeStr );

    //
    // FieldSizes is a comma separated list of FieldName:Size pairs
    //
    entry = _tcstok_s( fieldSizeStr, _T(","), &entrySave );

    while ( entry != NULL ) {

        //
        // Separate the FieldName from the Size
        //
        numPtr = _tcschr( entry, _T(':') );
        if( numPtr != NULL )
        {

            *numPtr = 0x00;
            numPtr++;

            //
            // Find FieldName in the event fields
            //
            found = FALSE;
            for( i = 0; i < SYSMON_MAX_EVENT_ID; i++ ) {

                for( j = 0; j < AllEvents[i]->FieldCount; j++) {

                    if( _tcscmp( entry, AllEvents[i]->FieldNames[j] ) == 0 )
                    {

                        //
                        // Set the entry to Size
                        //
                        value = _tstoi( numPtr );
                        if( value <= 0 )
                        {

                            _tprintf( _T("FieldSizes field '%s' has max size of %d.\n"), AllEvents[i]->FieldNames[j], value );
                            free( fieldSizeStr );
                            return FALSE;
                        }

                        g_VariableFieldSizes[i][j] = value;
                        found = TRUE;
                        break;
                    }
                }
            }
            if( !found )
            {

                _tprintf( _T("FieldSizes field '%s' is invalid.\n"), entry );
                free( fieldSizeStr );
                return FALSE;
            }
        }

        entry = _tcstok_s( NULL, _T(","), &entrySave );
    }

    free( fieldSizeStr );
    return TRUE;
}

//--------------------------------------------------------------------
//
// GetVariableFieldSize
//
// Retrieves variable field max size from array
//
//--------------------------------------------------------------------
int GetVariableFieldSize(ULONG EventId, ULONG FieldId)
{
    if (EventId >= SYSMON_MAX_EVENT_ID || FieldId >= SYSMON_MAX_EVENT_Fields)
        return -1;

    return g_VariableFieldSizes[EventId][FieldId];
}

//--------------------------------------------------------------------
//
// StringListDup
//
// Adapt a string list from string to multisz
//
//--------------------------------------------------------------------
PTCHAR
StringListDup(
    _In_ PTCHAR List,
    _In_opt_ PULONG FinalLength
    )
{
    SIZE_T  listLength = _tcslen( List );
    PTCHAR  base, dup, next, end;
    ULONG   dupLength = 0;

    if( listLength >= (ULONG_MAX-2)/sizeof(TCHAR) ) {

        _tprintf(_T("List too long: %s\n"), List );
        return NULL;
    }

    dupLength = (ULONG)(listLength + 2) * sizeof(TCHAR);
    dup = (PTCHAR) malloc( dupLength );

    if( dup == NULL ) {

        _tprintf( _T("Memory allocation failed\n") );
        return NULL;
    }

    if( FinalLength != NULL ) {

        *FinalLength = dupLength;
    }

    base = dup;
    ZeroMemory( dup, dupLength );
    end = (PTCHAR)((PBYTE)dup + dupLength);
    memcpy( dup, List, listLength * sizeof(TCHAR) );

    for( ;; ) {

        next = _tcschr( dup, _T(',') );
        if( next != NULL ) {

            if( *(next + 1) == _T(',') ) {

                memmove( next + 1, next + 2, (PBYTE)end - (PBYTE)(next + 2) );
                dup = next + 1;
                continue;
            }

            *(next++) = 0;
            dup = next;
        } else {
            next = _tcschr( dup, 0 );
            *(next+1) = 0;
            break;
        }
    }

    return base;
}

//--------------------------------------------------------------------
//
// HashingValidation
//
// Validate provided argument for hashing algorithm.
//
//--------------------------------------------------------------------
BOOLEAN
HashingValidation(
    _In_ int argc,
    _In_ TCHAR** argv,
    _In_ PCONFIGURATION_OPTION Option
    )
{
    PTCHAR  pos, valueStr;
    ULONG   flag, cur, index, length;

    if( !_tcsicmp( (PTCHAR)Option->Value, _T("*") ) ||
        !_tcsicmp( (PTCHAR)Option->Value, _T("all") ) ) {

        flag = ALGO_ALL;
    } else {

        valueStr = StringListDup( (PTCHAR)Option->Value, &length );

        if( valueStr == NULL ) {

            return FALSE;
        }

        flag = 0;

        for( index = 0;
             index < length && valueStr[index] != 0;
             index += (ULONG)_tcslen( valueStr + index ) + 1 ) {

            pos = valueStr + index;

            if( !_tcsicmp( pos, _T("sha1") ) ||
                !_tcsicmp( pos, _T("sha-1") ) ) {

                cur = ALGO_SHA1;
            } else if( !_tcsicmp( pos, _T("md5") ) ||
                       !_tcsicmp( pos, _T("md-5") ) ) {

                cur = ALGO_MD5;
            } else if( !_tcsicmp( pos, _T("sha256") ) ||
                       !_tcsicmp( pos, _T("sha-256") ) ) {

                cur = ALGO_SHA256;
            } else if( !_tcsicmp( pos, _T("imphash") ) ||
                       !_tcsicmp( pos, _T("imp-hash") ) ) {

                cur = ALGO_IMPHASH;
            } else {

                _tprintf( _T("Invalid hashing algorithm: %s\n"), pos );
                free( valueStr );
                return FALSE;
            }

            if( flag == 0 ) {

                flag = cur;
                continue;
            } else if( !(flag & ALGO_MULTIPLE) ) {

                flag = ALGO_GET_MASK( flag ) | ALGO_MULTIPLE;
            }
            flag |= ALGO_GET_MASK( cur );
        }

        free( valueStr );
    }

    //
    // Store the resulting flag
    //
    Option->Value = malloc( sizeof(flag) );

    if( Option->Value == NULL ) {

        _tprintf( _T("Memory allocation failed\n") );
        return FALSE;
    }

    memcpy( Option->Value, &flag, sizeof(flag) );
    Option->Size = sizeof(flag);
    Option->ValueAllocated = TRUE;
    return TRUE;
}


BOOLEAN
CheckRevocationValidation(
_In_ int argc,
_In_ TCHAR** argv,
_In_ PCONFIGURATION_OPTION Option
)
{
    return TRUE;
}

BOOLEAN
DnsLookupValidation(
    _In_ int argc,
    _In_ TCHAR** argv,
    _In_ PCONFIGURATION_OPTION Option
)
{
    return TRUE;
}



//--------------------------------------------------------------------
//
// ProcessAccessValidation
//
// Validate the process access input
//
//--------------------------------------------------------------------
BOOLEAN
ProcessAccessValidation(
_In_ int argc,
_In_ TCHAR** argv,
_In_ PCONFIGURATION_OPTION Option
)
{
    PTCHAR  stringDup, maskStr, current;
    ULONG   index, m_index, length = 0, opt_pos = 0, opt_len, opt_move;
    ULONG   pos, mask, masks[PAL_MAX_CONFIG_ITEMS] = {0,};

    stringDup = StringListDup( (PTCHAR) Option->Value, &length );

    if( stringDup == NULL ) {

        return FALSE;
    }

    Option->Size = length + sizeof(masks);
    if( Option->Size < length ) {

        _tprintf( _T("Memory allocation failed\n") );
        free( stringDup );
        return FALSE;
    }

    //
    // Allocate enough memory to hold the list + the mask
    //
    Option->Value = malloc( Option->Size );

    if( Option->Value == NULL ) {

        _tprintf( _T("Memory allocation failed\n") );
        free( stringDup );
        return FALSE;
    }

    ZeroMemory( Option->Value, Option->Size );
    Option->ValueAllocated = TRUE;

    //
    // Start after the mask array
    //
    opt_pos = sizeof(masks);

    //
    // Go through each entries
    //
    length /= sizeof(TCHAR);
    for( pos = 0, index = 0;
        index < length && stringDup[index] != 0 && pos < _countof(masks);
        index += (ULONG)_tcslen( stringDup + index ) + 1, pos++ ) {

        m_index = index;
        mask = (ULONG)-1;
        maskStr = NULL;
        current = stringDup + m_index;

        //
        // Find the mask position, skip ::
        //
        maskStr = _tcsrchr( current, _T(':') );

        if( maskStr != NULL ) {

            if( maskStr > current && maskStr[-1] == _T(':') ) {

                maskStr = NULL;
            } else {

                *(maskStr++) = 0;
                m_index = index + (ULONG)(maskStr - current);
            }
        }

        //
        // Translate the mask to an integer
        //
        if( maskStr != NULL ) {

            if( !_tcsnicmp( maskStr, _T("0x"), 2 ) ) {

                mask = _tcstoul( maskStr + 2, NULL, 16 );
            } else {

                mask = _tcstoul( maskStr, NULL, 10 );
            }
        }

        masks[pos] = mask;

        //
        // Check the string will fit (it should)
        //
        opt_len = (ULONG)(_tcslen( current ) + 1) * sizeof(TCHAR);
        if( opt_len + opt_pos < opt_pos ||
            opt_len + opt_pos >= Option->Size ) {

            _tprintf( _T("Invalid input for process access\n") );
            free( stringDup );
            return FALSE;
        }

        //
        // Skip escaped : characters
        //
        for( opt_move = opt_pos/sizeof(TCHAR);
            *current != 0 && (opt_move * sizeof(TCHAR)) < (opt_pos + opt_len);
            current++, opt_move++ )
        {
            ((PTCHAR)Option->Value)[opt_move] = *current;

            if( *current == _T(':') ) {

                D_ASSERT(*(current + 1) == _T(':'));
                current++;
            }
        }

        opt_pos = (opt_move + 1) * sizeof(TCHAR);

        if( maskStr != NULL ) {

            index = m_index;
        }
    }

    free(stringDup);

    if( pos >= _countof(masks) ) {

        _tprintf(_T("Too many entries to monitor for process access. Maximum is %d.\n"),
            (int)_countof(masks));
        return FALSE;
    }

    //
    // Add one char for the final multi sz mark and check the size can be updated
    //
    opt_pos += sizeof(TCHAR);

    if( Option->Size < opt_pos ) {

        _tprintf(_T("Invalid final input for process access\n"));
        return FALSE;
    }

    Option->Size = opt_pos;

    //
    // Finally copy the masks
    //
    memcpy((PBYTE)Option->Value, masks, sizeof(masks));
    return TRUE;
}


//--------------------------------------------------------------------
//
// ArchiveDirectoryValidation
//
// Validate the archive directory.
//
//--------------------------------------------------------------------
BOOLEAN
ArchiveDirectoryValidation(
    _In_ int argc,
    _In_ TCHAR** argv,
    _In_ PCONFIGURATION_OPTION Option
    )
{
    PTCHAR  archArg = (PTCHAR)Option->Value;
    if( _tcschr( archArg, _T('\\') ) ) {

        _tprintf( _T("Archive directory must be a single path component.\n") );
        return FALSE;
    }

    //
    // Store the resulting archive path
    //
    Option->Value = malloc( (_tcslen(archArg) + 10) * sizeof(TCHAR) );

    if( Option->Value == NULL ) {

        _tprintf( _T("Memory allocation failed\n") );
        return FALSE;
    }

    _stprintf( (PTCHAR)Option->Value, _T("\\%s\\"), archArg );
    Option->Size = (ULONG)(_tcslen(Option->Value) + 1) * sizeof(TCHAR);
    Option->ValueAllocated = TRUE;
    return TRUE;
}

//--------------------------------------------------------------------
//
// FieldSizesValidation
//
// Validate the archive directory.
//
//--------------------------------------------------------------------
BOOLEAN
FieldSizesValidation(
    _In_ int argc,
    _In_ TCHAR** argv,
    _In_ PCONFIGURATION_OPTION Option
    )
{
    if( LoadVariableFieldSizes( Option->Value ) ) {

        if (Option->Value == NULL) {
            return TRUE;
        }

        PTCHAR tmp = Option->Value;
        Option->Value = malloc((_tcslen(tmp) + 1) * sizeof(TCHAR));
        if (Option->Value == NULL) {
            return FALSE;
        }

        _tcscpy(Option->Value, tmp);
        Option->ValueAllocated = TRUE;
        return TRUE;
    }

    return FALSE;
}

//--------------------------------------------------------------------
//
// StringListValidation
//
// Validate a classic string list.
//
//--------------------------------------------------------------------
BOOLEAN
StringListValidation(
    _In_ int argc,
    _In_ TCHAR** argv,
    _In_ PCONFIGURATION_OPTION Option
    )
{
    Option->Value = StringListDup( (PTCHAR) Option->Value, &Option->Size );

    if( Option->Value == NULL ) {

        return FALSE;
    }

    Option->ValueAllocated = TRUE;
    return TRUE;
}



typedef BOOLEAN (* VAL_CALLBACK)(
    _In_ int argc,
    _In_ TCHAR** argv,
    _In_ PCONFIGURATION_OPTION Option
    );

typedef struct {
    PCONFIGURATION_OPTION option;
    VAL_CALLBACK callback;
} OPTION_VALIDATE;

//
// Validation callbacks
//
OPTION_VALIDATE optionValidation[] = {
    { &ConfigOptions.HashAlgorithms, HashingValidation },
    { &ConfigOptions.ProcessAccess, ProcessAccessValidation },
    { &ConfigOptions.CheckRevocation, CheckRevocationValidation },
    { &ConfigOptions.DnsLookup, DnsLookupValidation },
    { &ConfigOptions.ArchiveDirectory, ArchiveDirectoryValidation },
    { &ConfigOptions.FieldSizes, FieldSizesValidation },
};


//--------------------------------------------------------------------
//
// IsSwitch
//
// Checks if a character is a switch identifier or not.
//
//--------------------------------------------------------------------
BOOLEAN
IsSwitch(
    TCHAR c
    )
{
    BOOLEAN ret = FALSE;

#if defined _WIN64 || defined _WIN32
    if( c == _T('/') || c == _T('-') ) {
        ret = TRUE;
    }

#elif defined __linux__
    if( c == '-' ) {
        ret = TRUE;
    }
#endif

    return ret;
}


//--------------------------------------------------------------------
//
// ParseCommandLine
//
// Automatically parse the command-line from pre-generated data from
// manifest.xml and validate it.
//
//--------------------------------------------------------------------
BOOLEAN
ParseCommandLine(
	_In_ int argc,
	_In_ TCHAR** argv,
	_In_ PVOID* Rules,
	_In_ PULONG RulesSize,
	_In_ PTCHAR *ConfigFile,
	_In_ PTCHAR ConfigHash,
	_In_ SIZE_T ConfigHashSize
	)
{
	int			 i, j;
	SIZE_T		 z, len;
	BOOLEAN		 lastChar, skip, opt, excl = FALSE;
	PTCHAR		 configuration = NULL;
#if !defined(SYSMON_SHARED) && !defined(SYSMON_PUBLIC)
	TCHAR        dumpFile[MAX_PATH];
	FILE*        dumpF = NULL;
	PVOID        ruleCheck = NULL;
	size_t       num_written, num_read;
	PTCHAR       internalRepresentation = NULL;
#if defined _WIN64 || defined _WIN32
	struct _stat dumpStat;
#elif defined __linux__
    struct stat  dumpStat;
#endif
#endif

	//
	// Parse the command line
	//
	*ConfigFile = NULL;
	for( i = 1; i < argc; i++ ) {

		// Is not a switch
        if( !IsSwitch( argv[i][0] ) ) {

			return FALSE;
		}

		j = 1;
		skip = FALSE;

		while( skip == FALSE && argv[i][j] != 0 ) {

			//
			// Go through known configuration options
			//
			for( z = 0; z < ConfigOptionTypeCount && skip == FALSE; z++ ) {

				if( ConfigOptionType[z].Switch == NULL ) {

					continue;
				}

				//
				// Support long switches only if it starts with a / or -
				//
				len = _tcslen( ConfigOptionType[z].Switch );
				if( j != 1 && len > 1 ) {

					continue;
				}

				//
				// Match the configuration and act on it
				//
				if( _tcsnicmp( &argv[i][j], ConfigOptionType[z].Switch, len ) != 0 ) {

					continue;
				}

				//
				// Ensure exclusive switches are not used together
				//
				if( ConfigOptionType[z].Exclusive ) {

					if( excl ) {

						return FALSE;
					}

					excl = TRUE;
				}

				ConfigOptionType[z].Option->IsSet = TRUE;
				j += (int)len;
				lastChar = ( argv[i][j] == 0 );
				opt = TRUE;

				switch( ConfigOptionType[z].ValueFlag ) {
				case ConfigValueRequired:
					if( !lastChar ) {

						return FALSE;
					}
					opt = FALSE;
					__fallthrough;

				case ConfigValueOptional:
					if( !lastChar ) {

						break;
					}

					//
					// No arguments after
					//
					if( ( i + 1 ) >= argc ) {

						if( !opt ) {

							return FALSE;
						}
						break;
					}

					//
					// Switch after
					//
					if( opt ) {

                        if( IsSwitch( argv[i + 1][0] ) ) {

							break;
						}
					}

					//
					// Value already set before
					//
					if( ConfigOptionType[z].Option->Value != NULL ) {

						return FALSE;
					}

					i++;
					ConfigOptionType[z].Option->Value = argv[i];
					ConfigOptionType[z].Option->Size = (ULONG)(_tcslen(argv[i]) + 1) * sizeof(TCHAR);
					skip = TRUE;
					break;
                default:
                    break;
				}

				//
				// Break on long switches
				//
				if( len > 1 || lastChar ) {

					skip = TRUE;
					break;
				}
			}

			//
			// If no match was found, just fail
			//
			if( z == ConfigOptionTypeCount ) {

				return FALSE;
			}
		}
	}

	//
	// Is there a configuration file?
	//
	if( OPT_SET(Install) ) {

		configuration = OPT_VALUE(Install);
	} else if ( OPT_SET(Configuration) ) {

#if defined _WIN64 || defined _WIN32
		OPT_SET(Install) = TRUE;
#endif
		configuration = OPT_VALUE(Configuration);
	}

	//
	// Parse configuration
	//
	if( !ApplyConfigurationFile( configuration, Rules, RulesSize, FALSE ) ) {

		return FALSE;
	}
	else {
		
		if( configuration != NULL ) {

			// 
			// Get hash for inclusion in event log
			//
			*ConfigFile = configuration; 
#if defined _WIN64 || defined _WIN32
			GetFileHash( SysmonCryptoCurrent(), configuration, ConfigHash, ConfigHashSize, TRUE );
#endif

#if !defined(SYSMON_SHARED) && !defined(SYSMON_PUBLIC)
			// If the InternalRepresentation switch is present, then either dump the internal representation
			// to a file if the given filename does not already exist;
			// Or check the internal representation against the supplied filename parameter.
			// In both cases, exit after taking action, and exit on error.
			if (OPT_SET(InternalRepresentation)) {
				internalRepresentation = OPT_VALUE(InternalRepresentation);
				printf("Dump/Check Internal Representation\nRulesSize = " PRINTF_ULONG_FS "\n", *RulesSize);
				if (!internalRepresentation || !*internalRepresentation) {
					printf("Internal Representation file name missing\n");
					exit(-1);
				}
				_stprintf_s(dumpFile, MAX_PATH, _T("%s"), internalRepresentation);
				if (_tstat(dumpFile, &dumpStat) == 0) {
					// Check
					_tprintf(_T("Checking with: '%s'\n"), dumpFile);
					if ((unsigned long)dumpStat.st_size != *RulesSize) {
						_tprintf(_T("File size = " PRINTF_LONGLONG_FS ", but expected = " PRINTF_ULONG_FS "\n"), (LONGLONG)dumpStat.st_size, *RulesSize);
						exit(-2);
					}
					dumpF = _tfopen(dumpFile, _T("rb"));
					if (!dumpF) {
						printf("Cannot read input file\n");
						exit(-1);
					}
					ruleCheck = malloc(*RulesSize);
					if (!ruleCheck) {
						printf("Cannot allocate memory for rule check\n");
						fclose(dumpF);
						exit(-1);
					}
					num_read = fread(ruleCheck, 1, *RulesSize, dumpF);
					printf("Read " PRINTF_ULONGLONG_FS " bytes\n", (ULONGLONG)num_read);
					fclose(dumpF);
					if (memcmp(*Rules, ruleCheck, *RulesSize)) {
						printf("File contents DOES NOT match internal representation\n");
						free(ruleCheck);
						exit(-2);
					}
					printf("File contents CORRECTLY match internal representation\n");
					free(ruleCheck);
					exit(0);
				}
				else {
					// Dump
					_tprintf(_T("Dumping to: '%s'\n"), dumpFile);
					dumpF = _tfopen(dumpFile, _T("wb"));
					if (!dumpF) {
						printf("Cannot create output file\n");
						exit(-1);
					}
					num_written = fwrite(*Rules, 1, *RulesSize, dumpF);
					printf("Written " PRINTF_ULONGLONG_FS " bytes\n", (ULONGLONG)num_written);
					fclose(dumpF);
					exit(0);
				}
			}
#endif
		}
	}

	//
	// Validate options
	//
	for( z = 0; z < _countof(optionValidation); z++ ) {

		if( optionValidation[z].option->IsSet &&
			optionValidation[z].option->Value &&
			!optionValidation[z].callback( argc, argv,
										   optionValidation[z].option ) ) {

			return FALSE;
		}
	}
	return TRUE;
}
