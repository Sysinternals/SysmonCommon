// Set of utilities for make it easier to build unittests.
#if defined __linux__
#include "linuxTypes.h"
#include <unistd.h>
#define TRUE true
#define FALSE false
#define ULONG_MAX 0xFFFFFFFFUL
#endif
#include "utils.h"

#if defined _WIN64 || defined _WIN32
#include <io.h>
#elif defined __linux__
#include <stdio.h>
#include <string.h>
#endif
#include <cstdio>
#include <codecvt>
#include <fstream>
#include <locale>

#if defined(_UNICODE)
// tstring2string is an helper function to translate a TCHAR string to std::string.
std::string tstring2string(_In_ const tstring str)
{
    std::wstring_convert<std::codecvt_utf8<TCHAR>, TCHAR> converter;
    return converter.to_bytes(str);
}

// string2tstring is an helper function to translate a std::string to TCHAR string.
tstring string2tstring(_In_ std::string str)
{
    std::wstring_convert<std::codecvt_utf8<TCHAR>, TCHAR> converter;
	return converter.from_bytes(str);
}
#endif

// ReadBinaryFile is an helper function to get binary data from a file.
BOOL ReadBinaryFile(_In_ const tstring& file,
					_Out_ std::vector<CHAR>& output)
{
	std::ifstream bin(file, std::ios::binary);
	if( !bin ) {
		_tprintf(_T("Failed to open: %s"), file.c_str());
		return FALSE;
	}

	bin.seekg(0, std::ios::end);
	std::streamoff len = bin.tellg();
	if( len < 0 || len > (int64_t)ULONG_MAX) {
		bin.close();
#if defined _WIN64 || defined _WIN32
		_tprintf(_T("File is too big %s: %llu"), file.c_str(), len);
#elif defined __linux__
		_tprintf(_T("File is too big %s: %lu"), file.c_str(), len);
#endif
		return FALSE;
	}
	bin.seekg(0, std::ios::beg);

    ULONG bufferSize = static_cast<ULONG>(len);
    output.resize(bufferSize);
	bin.read(&output[0], bufferSize);
	bin.close();
	return TRUE;
}

// WriteTempStringFile creates a temporary file and set the content.
BOOL WriteTempStringFile(_In_ const PCHAR content,
						 _Out_ tstring& tmpFile)
{
	CHAR file[MAX_PATH + 1];
#if defined _WIN64 || defined _WIN32
	errno_t err = tmpnam_s(file, _countof(file));
#elif defined __linux__
    strcpy(file, "/tmp/sysmon_tmp_XXXXXX");
    int fd = mkstemp(file);
    errno_t err = 0;
    if (fd < 0) {
        err = 1;
    } else {
        close(fd);
    }
#endif
	if( err ) {
		_tprintf(_T("Failed to generate temp file: %d"), err);
		return FALSE;
	}
	std::ofstream tmp(file, std::ios::out);
	if( !tmp ) {
#if defined _WIN64 || defined _WIN32
		_tprintf(_T("Failed to open temp file: %S"), file);
#elif defined __linux__
		_tprintf(_T("Failed to open temp file: %s"), file);
#endif
		return FALSE;
	}

	tmp.write(content, strlen(content));
	tmp.close();

	std::string strFile(file);
	tmpFile = string2tstring(strFile);
	return TRUE;
}
