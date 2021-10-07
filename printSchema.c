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
// printSchema.c
//
// Prints the event schemas
//
//====================================================================

#include "stdafx.h"

extern char _binary_manifest_xml_start[];
extern char _binary_manifest_xml_end[];

//--------------------------------------------------------------------
//
// LoadFileInResource
//
//--------------------------------------------------------------------
#if defined _WIN64 || defined _WIN32
BOOL LoadFileInResource(TCHAR* name, TCHAR* type, DWORD* size, char** data)
{
    HMODULE handle = GetModuleHandle(NULL);
    HRSRC rc = FindResource(handle, name, type);
    HGLOBAL rcData = LoadResource(handle, rc);
    *size = SizeofResource(handle, rc);
    const char* dataRc = (const char*)LockResource(rcData);
    *data = (char*)malloc(*size + 2);
    if (NULL == *data)
        return FALSE;

    memset(*data, 0, *size + 2);
    memcpy(*data, dataRc, *size);
    return TRUE;
}
#endif

void PrintSchema()
{
    //
    // Load the schema text
    //
    PTCHAR schema;
    PTCHAR schemaVersion = (PTCHAR)OPT_VALUE( PrintSchema );
    DWORD size;

#if defined _WIN64 || defined _WIN32
    if (!LoadFileInResource( _T( "Sysmonschema" ), _T( "XML" ), &size, (char **) &schema ))
    {
        printf("Out of memory\n");
        exit(E_OUTOFMEMORY);
    }


#elif defined __linux__
    size = _binary_manifest_xml_end - _binary_manifest_xml_start;
    schema = (PTCHAR)malloc(size + 1);
    if (schema == NULL) {
        printf("Out of memory\n");
        exit(E_OUTOFMEMORY);
    }
    memcpy(schema, _binary_manifest_xml_start, size);
    schema[size] = 0x00;
#endif

    BOOLEAN dumpAll = schemaVersion && !_tcsicmp( schemaVersion, _T( "all" ) );
    PTCHAR curSchema = _tcsstr( schema, _T( "<manifest" ) );
    do {

        if( schemaVersion ) {

            do {

                PTCHAR versionString = _tcsstr( curSchema, _T( "schemaversion=" ) ) + _tcslen( _T( "schemaversion=\"" ) );
                if( dumpAll || !_tcsncmp( versionString, schemaVersion, _tcslen( schemaVersion ) ) ) {
                    break;
                }

                curSchema = _tcsstr( curSchema + _tcslen( _T( "<manifest" ) ), _T( "<manifest" ) );

            } while( curSchema );
        }
        if( curSchema ) {

            TCHAR terminatingChar = *(_tcsstr( curSchema, _T( "</manifest>" ) ) + _tcslen( _T( "</manifest>" ) ));
            *(_tcsstr( curSchema, _T( "</manifest>" ) ) + _tcslen( _T( "</manifest>" ) )) = 0;
            _tprintf_s( _T( "%s\n" ), _tcsstr( curSchema, _T( "<manifest" ) ) );

            *(_tcsstr( curSchema, _T( "</manifest>" ) ) + _tcslen( _T( "</manifest>" ) )) = terminatingChar;
            curSchema = _tcsstr( curSchema + _tcslen( _T( "<manifest" ) ), _T( "<manifest" ) );
        }
        else {

            _tprintf( _T( "There is no schema that matches that version.\n" ) );
        }
    } while( dumpAll && curSchema );
    free( schema );
}

