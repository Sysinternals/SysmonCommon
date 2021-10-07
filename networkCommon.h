/*
    SysmonCommon

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#pragma once

#include <stdio.h>
#include <list>
#include <queue>
#include <string>
#include <map>
#include <string.h>

#if defined __linux__
#include "linuxTypes.h"
#include "linuxHelpers.h"
typedef std::string _bstr_t;
#endif


#if defined _WIN64 || defined _WIN32

#include <winsock2.h>
#include <ws2tcpip.h>
#include <comdef.h>
#include <guiddef.h>
#include <wmistr.h>
#include <tdh.h>
#include <wbemidl.h>
#include <evntrace.h>

#include "PerfCounter.h"

extern "C" {
#include "pscommon.h"
#include "service.h"
#include "..\sysmonCommon\ioctlcmd.h"
}


#pragma comment(lib, "wbemuuid.lib")
#endif

bool CreateNetworkEvent( DWORD processId, DWORD threadId, EVENT_TYPE_NETWORK type, bool isTcp,
						LARGE_INTEGER timestamp, ULONGLONG duration, DWORD length,
						bool srcIsIpV4, const BYTE* srcAddr, WORD srcPort,
						bool dstIsIpV4, const BYTE* dstAddr, WORD dstPort,
						const void* const stackEntries[], DWORD stackCnt,
						const _bstr_t& details );

//
// String.h
//

// 
// A CBlob is a reference-counted blob of data
//
class CBlob
{
	class CData
	{
		LONG		m_RefCnt;
		DWORD		m_Size;
		BYTE		m_Data[ 1 ];

		// Never allow copy
		CData( const CData & s );
		// destructor is private (use Release instead)
		~CData()
		{
			D_ASSERT(false);
		}

	public:
		static CData * NewData( size_t size );
		static CData * NewData( const void * data, size_t size );
		static CData * NewData( const void * data1, size_t size1, const void * data2, size_t size2 );
		LONG RefCnt() const;
		LONG AddRef();
		LONG Release();
		const void * Data() const;
		DWORD Size() const;
	};

	CData	*	m_Data;

public:

	// constructor
	inline CBlob() : m_Data( NULL )
	{
	}

	inline CBlob( size_t size ) 
		: m_Data( CData::NewData(size) )
	{
	}

	inline CBlob( const void * data, size_t size ) 
		: m_Data( CData::NewData(data,size) )
	{
	}

	inline CBlob( const void * data1, size_t size1, const void * data2, size_t size2 ) 
		: m_Data( CData::NewData(data1,size1,data2,size2) )
	{
	}

	inline CBlob( const CBlob & src ) : m_Data( src.m_Data )
	{
		if ( m_Data )
			m_Data->AddRef();
	}

	// destructor
	inline ~CBlob()
	{
		if ( m_Data )
			m_Data->Release();
	}

	inline const void * Data() const
	{
		if ( m_Data )
			return m_Data->Data();
		else
			return NULL;
	}

	// assignment
	void operator =( const CBlob & src );
	void Assign( const void * data, size_t size );
	void Assign( const void * data1, size_t size1, const void * data2, size_t size2 );
	void Append( const void * data, DWORD size );
	inline DWORD Size() const
	{
		return m_Data ? m_Data->Size() : 0;
	}

	// Relations
	bool operator ==( const CBlob & other ) const;
	int Compare( const CBlob & other ) const;
	inline bool operator < ( const CBlob & other ) const
	{
		return Compare( other ) < 0;
	}
	static int MemCompare( const CBlob & b1, const CBlob & b2 );
};

class CString
{
	CBlob	m_Blob;
#if _DEBUG
	const WCHAR * text;
#endif

	// return number of bytes in string, including null terminator
	static size_t ByteLen( const TCHAR * str );

public:
	CString()
	{
#if _DEBUG
		text = NULL;
#endif
	}

	// we construct a string from a buffer and length by concatenating the buffer with a null-terminated string
	CString( const TCHAR * str, size_t len ) : m_Blob( str, len*sizeof(TCHAR), _T(""), len?sizeof(TCHAR):0 )
	{
#if _DEBUG
		text = *this;
#endif
	}
	
	// special constructor for reading compacted strings
	CString( const BYTE * str, size_t len );
	inline CString( const TCHAR * str ) : m_Blob(str,ByteLen(str))
	{
#if _DEBUG
		text = *this;
#endif
	}
	DWORD length() const;
	const CString & operator =( const TCHAR * str );
	const CString & operator =( const CString & str )
	{
		m_Blob = str.m_Blob;
#if _DEBUG
		text = *this;
#endif
		return *this;
	}

	void operator +=( const TCHAR * str );
	void operator +=( const CString & str );
	int Diff( const CString & other) const;
	bool operator < (const CString & other) const;
	bool operator == (const CString & other) const;

	// extract string
	operator const TCHAR * () const;
	CString operator + ( const CString & other ) const;
	friend CString operator + ( const TCHAR * s1, const CString & s2 );
};

//
// Critical.h
//

class CCritical
{
private:
	mutable CRITICAL_SECTION	m_Critical;

public:
	inline CCritical()
	{
		InitializeCriticalSection( &m_Critical );
	}
	inline CCritical( const CCritical & other )
	{
		// this occurs when we copy an object that contains a critical section
#if defined _WIN64 || defined _WIN32
		D_ASSERT( !other.IsCritical() );
#endif
		InitializeCriticalSection( &m_Critical );
	}
	inline ~CCritical()
	{
		DeleteCriticalSection( &m_Critical );
	}
	CCritical & operator = ( const CCritical & other )
	{
		// this occurs when we copy an object that contains a critical section
#if defined _WIN64 || defined _WIN32
		D_ASSERT( !other.IsCritical() );
#endif
		InitializeCriticalSection( &m_Critical );
#if defined __linux__
        return *this;
#endif
	}

	inline bool TryEnter() const
	{
		return TryEnterCriticalSection( &m_Critical ) != FALSE;
	}
	inline void Enter() const
	{
		EnterCriticalSection( &m_Critical );
	}
	inline void Leave() const
	{
		LeaveCriticalSection( &m_Critical );
	}

#if defined _WIN64 || defined _WIN32
	bool IsCritical() const
	{
		return m_Critical.RecursionCount > 0 && m_Critical.OwningThread == (HANDLE)UlongToPtr(GetCurrentThreadId());
	}
#endif
};

class CEnterCritical
{
	const CCritical & m_Critical;
public:
	inline CEnterCritical( const CCritical & lock ) : m_Critical(lock)
	{
		m_Critical.Enter();
	}
	inline CEnterCritical( const CCritical * lock ) : m_Critical(*lock)
	{
		m_Critical.Enter();
	}
	inline ~CEnterCritical()
	{
		m_Critical.Leave();
	}
};

#if defined _WIN64 || defined _WIN32
//
// Serialize.h
//

class CSerialize
{
	BYTE *	m_Base;
	size_t	m_Max;
	size_t	m_Offset;

public:
	CSerialize( BYTE * Ptr, size_t Max ) : m_Base( Ptr ), m_Max( Max ), m_Offset( 0 )
	{
	}

	inline DWORD Count() const
	{
		return (DWORD)m_Offset;
	}

	inline bool Buffer() const
	{
		return m_Base != NULL;
	}

	inline void Overwrite( DWORD offset, DWORD value )
	{
		if ( m_Base )
			*(DWORD *)(m_Base + offset) = value;
	}

	inline void WriteBytes( const void * buf, DWORD len )
	{
		if ( m_Base )  {
			if ( m_Offset + len > m_Max )
				throw ERROR_INSUFFICIENT_BUFFER;
			memcpy( m_Base+m_Offset, buf, len );
		}
		m_Offset += len;
		D_ASSERT( m_Base == NULL  ||  m_Offset <= m_Max ); 
	}
	inline void ReadBytes( void * buf, DWORD len )
	{
		if ( m_Offset + len > m_Max )
			throw ERROR_INSUFFICIENT_BUFFER;
		memcpy( buf, m_Base+m_Offset, len );
		m_Offset += len;
		D_ASSERT( m_Offset <= m_Max ); 
	}
	inline BYTE * SkipBytes( size_t len )
	{
		if ( m_Base )  {
			if ( m_Offset + len > m_Max )
				throw ERROR_INSUFFICIENT_BUFFER;
		}
		BYTE * pos = m_Base + m_Offset;
		m_Offset += len;
		return pos;
	}


	inline void WriteDword( DWORD d )
	{
		WriteBytes( &d, sizeof d );
	}
	inline void ReadDword( DWORD & d )
	{
		ReadBytes( &d, sizeof d );
	}

	inline void WriteAddress( const void * ptr )
	{
		WriteBytes( &ptr, sizeof ptr );
	}
	inline void ReadAddress( void * &ptr )
	{
		ReadBytes( &ptr, sizeof ptr );
	}

	inline void WriteLargeInt( ULONGLONG l )
	{
		WriteBytes( &l, sizeof l );
	}
	inline void ReadLargeInt( ULONGLONG & l )
	{
		ReadBytes( &l, sizeof l );
	}

	inline void WriteLargeInt( LONGLONG l )
	{
		WriteBytes( &l, sizeof l );
	}
	inline void ReadLargeInt( LONGLONG & l )
	{
		ReadBytes( &l, sizeof l );
	}


	inline void WriteFileTime( FILETIME ft )
	{
		WriteBytes( &ft, sizeof ft );
	}
	inline void ReadFileTime( FILETIME & ft )
	{
		ReadBytes( &ft, sizeof ft );
	}
	

	inline void WriteBool( bool b )
	{
		WriteBytes( &b, sizeof b );
	}
	inline void ReadBool( bool & b )
	{
		ReadBytes( &b, sizeof b );
	}

	inline void WriteGuid( const GUID & guid )
	{
		WriteBytes( &guid, sizeof guid );
	}
	inline void ReadGuid( GUID & guid )
	{
		ReadBytes( &guid, sizeof guid );
	}

	inline void WriteLuid( const LUID & luid )
	{
		WriteBytes( &luid, sizeof luid );
	}
	inline void ReadLuid( LUID & luid )
	{
		ReadBytes( &luid, sizeof luid );
	}

	void WriteString( const WCHAR * ptr );
	void ReadString( WCHAR *& ptr );
	void AssignString( const WCHAR *& ptr );
	void WriteCString( const CString & string );
	void ReadCString( CString & string );
	void WriteBlob( const CBlob & blob );
	void ReadBlob( CBlob & blob );
	void WriteACL( const ACL * ptr );
	void ReadACL( ACL *& ptr );
	void AssignACL( const ACL *& ptr );
	void WriteSID( const SID * ptr );
	void ReadSID( SID *& ptr );
	void AssignSID( const SID *& ptr );
	void WriteSecurityDescriptor( PSECURITY_DESCRIPTOR sd );
	void ReadSecurityDescriptor( PSECURITY_DESCRIPTOR & sd );
};
#endif

//
// Resolver.h
//

class CHostNameResolver : public CCritical
{
	struct ADDRESS {
		BYTE	addr[ 16 ];

		bool operator < (const ADDRESS & other) const
		{
			return memcmp( addr, other.addr, 16 ) < 0;
		}
	};

	LONG						m_ThreadCount;

	typedef std::map<ADDRESS,CString>	ADDR_MAP;
	ADDR_MAP							m_AddrMap;

	struct LOOKUP_CONTEXT {
		CHostNameResolver	*	This;
		ADDRESS					Address;
		bool					IsV6;
		CString				*	Result;
	};

	typedef std::queue<LOOKUP_CONTEXT*>	ADDR_QUEUE;
	ADDR_QUEUE							m_AddrQueue;

#if defined _WIN64 || defined _WIN32
	static unsigned __stdcall AddThread( void * Context );
#elif defined __linux__
	static void *AddThread( void * Context );
#endif


public:
	CHostNameResolver() : m_ThreadCount(0)
	{
	}

	bool AddAddress( const BYTE * addr, bool isV6 );
	CString ResolveAddress( const BYTE * addr, bool isV6 );
	~CHostNameResolver();

#if defined _WIN64 || defined _WIN32
	void Serialize( CSerialize & out ) const;
	void Deserialize( CSerialize & out );
#endif
};



class CPortNameResolver : public CCritical
{
	LONG						m_ThreadCount;

	typedef std::map<DWORD,CString>		PORT_MAP;
	PORT_MAP							m_PortMap;

	struct LOOKUP_CONTEXT {
		CPortNameResolver	*	This;
		WORD					Port;
		bool					IsTCP;
		CString				*	Result;
	};

	typedef std::queue<LOOKUP_CONTEXT*>	PORT_QUEUE;
	PORT_QUEUE							m_PortQueue;

#if defined _WIN64 || defined _WIN32
	static unsigned __stdcall AddThread( void * Context );
#elif defined __linux__
	static void *AddThread( void * Context );
#endif

public:
	CPortNameResolver() : m_ThreadCount(0)
	{
	}

	bool AddPort( WORD port, bool isTCP );
	CString ResolvePort( WORD port, bool isTCP );
	~CPortNameResolver();

#if defined _WIN64 || defined _WIN32
	void Serialize( CSerialize & out ) const;
	void Deserialize( CSerialize & out );
#endif
};



extern CHostNameResolver	g_HostNameResolver;
extern CPortNameResolver	g_PortNameResolver;

DWORD NetworkEvent(
    _In_ PLARGE_INTEGER Time,
    _In_ DWORD OwnerPID,
    _In_ const TCHAR* user,
    _In_ BOOLEAN isTcp,
    _In_ ULONG isInitiated,
    _In_ ULONG srcIpv6,
    _In_ const TCHAR* srcAddrIp,
    _In_ const TCHAR* srcHostname,
    _In_ WORD srcPort,
    _In_ const TCHAR* srcPortname,
    _In_ ULONG dstIpv6,
    _In_ const TCHAR* dstAddrIp,
    _In_ const TCHAR* dstHostname,
    _In_ WORD dstPort,
    _In_ const TCHAR* dstPortname);


//
// Misc.h
//

CString IPAddressToString( const BYTE * addr, bool isV6 );
CString	IPAddressToHostName( const BYTE * addr, bool isV6, WORD port, bool isTCP );
CString IntToString( LONGLONG value );
CString LookupAccountNameFromPID(
	_In_ DWORD ProcessId,
	_In_ PLARGE_INTEGER Timestamp
	);

