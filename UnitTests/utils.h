// Set of utilities for make it easier to build unittests.
#pragma once

#if defined _WIN64 || defined _WIN32
#include <windows.h>
#include <tchar.h>
#endif

#include <string>
#include <vector>

typedef std::basic_string<TCHAR> tstring;

// tstring2string is an helper function to translate a TCHAR string to std::string.
// string2tstring is an helper function to translate a std::string to TCHAR string.
#ifdef _UNICODE
std::string tstring2string(_In_ const tstring str);
tstring string2tstring(_In_ std::string str);
#else
#define tstring2string(str) str
#define string2tstring(str) str
#endif

// ReadBinaryFile is an helper function to get binary data from a file.
BOOL ReadBinaryFile(_In_ const tstring& file, _Out_ std::vector<CHAR>& output);

// WriteTempStringFile creates a temporary file and set the content.
BOOL WriteTempStringFile(_In_ const PCHAR content, _Out_ tstring& tmpFile);
