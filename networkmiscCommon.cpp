/*
    SysmonCommon

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#if defined __linux__
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include "linuxTypes.h"
#include "stdafx.h"
#include "eventsCommon.h"

LONG
InterlockedIncrement(
    LONG volatile *Addend
    )
{
    (*Addend)++;
    return *Addend;
}

LONG
InterlockedDecrement(
    LONG volatile *Addend
    )
{
    (*Addend)--;
    return *Addend;
}

int min(int a, int b) { return (a < b ? a : b); }

#define SOCKADDR struct sockaddr
#endif

#include "networkCommon.h"

#define MAX_THREADS 	50
#define MAX_QUEUE_SIZE	400

//
// String.cpp
//

CBlob::CData * CBlob::CData::NewData( size_t size )
{
	if ( size == 0 )
		return NULL;
	// Allocate a new buffer
	CData * buffer = (CData *) new BYTE[ sizeof(CData) + size - 1 ];
	// initialize
	buffer->m_RefCnt	= 1;
	buffer->m_Size		= (DWORD)size;
	return buffer;
}

CBlob::CData * CBlob::CData::NewData( const void * data, size_t size )
{
	if ( size == 0 )
		return NULL;
	// Allocate a new buffer
	CData * buffer = (CData *) new BYTE[ sizeof(CData) + size - 1 ];
	// initialize
	buffer->m_RefCnt	= 1;
	buffer->m_Size		= (DWORD)size;
	memcpy( buffer->m_Data, data, size );
	return buffer;
}

CBlob::CData * CBlob::CData::NewData( const void * data1, size_t size1, const void * data2, size_t size2 )
{
	if ( size1 + size2 == 0 )
		return NULL;
	// Allocate a new buffer
	CData * buffer = (CData *) new BYTE[ sizeof(CData) + size1 + size2 - 1 ];
	// initialize
	buffer->m_RefCnt	= 1;
	buffer->m_Size		= (DWORD)(size1+size2);
	memcpy( buffer->m_Data,       data1, size1 );
	memcpy( buffer->m_Data+size1, data2, size2 );
	return buffer;
}

LONG CBlob::CData::RefCnt() const
{
	return m_RefCnt;
}

LONG CBlob::CData::AddRef()
{
	return InterlockedIncrement( &m_RefCnt );
}

LONG CBlob::CData::Release()
{
	if ( InterlockedDecrement( &m_RefCnt ) == 0 ) {
		delete [](BYTE *)this;
		return 0;
	}
	return m_RefCnt;
}

const void * CBlob::CData::Data() const
{ 
	return m_Data; 
}

DWORD CBlob::CData::Size() const
{
	return m_Size;
}



// assignment
inline void CBlob::operator =( const CBlob & src ) 
{
	if ( m_Data )
		m_Data->Release();
	m_Data = src.m_Data;
	if ( m_Data )
		m_Data->AddRef();
}

inline void CBlob::Assign( const void * data, size_t size ) 
{
	// allocate before releasing in case the
	// data we're copying into the allocation
	// is part of the data we're releasing
	CData * tmp = CData::NewData( data, size );
	if ( m_Data )
		m_Data->Release();
	m_Data = tmp;
}

inline void CBlob::Assign( const void * data1, size_t size1, const void * data2, size_t size2 )
{
	*this = CBlob( data1, size1, data2, size2 );
}

inline void CBlob::Append( const void * data, DWORD size )
{
	if ( size == 0 )  {
		// nothing
	} else if ( Size() == 0 )  {
		Assign( data, size );
	} else {
		Assign( m_Data, m_Data->Size(), data, size );
	}
}


// Relations
inline bool CBlob::operator ==( const CBlob & other ) const
{
	return Size() == other.Size()  &&  memcmp( Data(), other.Data(), Size() ) == 0;
}

int CBlob::Compare( const CBlob & other ) const
{
	int diff = Size() - other.Size();
	if ( diff )
		return diff >= 0 ? 1 : -1;
	return memcmp( Data(), other.Data(), Size() );
}

int CBlob::MemCompare( const CBlob & b1, const CBlob & b2 )
{
	int size = min( b1.Size(), b2.Size() );
	int diff = memcmp( b1.Data(), b2.Data(), size );
	if ( diff )
		return diff;
	size = b1.Size() - b2.Size();
	return size >= 0 ? 1 : -1;
}



	// return number of bytes in string, including null terminator
size_t CString::ByteLen( const TCHAR * str )
{
	return str ? (_tcslen(str)+1)*sizeof str[0] : 0;
}

	
// special constructor for reading compacted strings
CString::CString( const BYTE * str, size_t len ) : m_Blob( (len+1)*sizeof(TCHAR) )
{
	TCHAR * textPtr = (TCHAR *)m_Blob.Data();
	for ( DWORD i = 0; i < len; ++i )  {
		textPtr[i] = str[i];
	}
	textPtr[len] = 0;
#if _DEBUG
	this->text = *this;
#endif
}


DWORD CString::length() const
{
	DWORD len = m_Blob.Size();
	if ( len )
		len -= sizeof(TCHAR);
	return len / sizeof(TCHAR);
}

const CString & CString::operator =( const TCHAR * str )
{
	m_Blob.Assign( str, ByteLen(str) );
#if _DEBUG
	text = *this;
#endif
	return *this;
}

void CString::operator +=( const TCHAR * str )
{
	if ( str[0] == 0 )
		return;
	if ( m_Blob.Size() > sizeof(TCHAR) )
		m_Blob.Assign( m_Blob.Data(), m_Blob.Size() - sizeof(TCHAR), str, ByteLen(str) );
	else
		m_Blob.Assign( str, ByteLen(str) );
#if _DEBUG
	text = *this;
#endif
}

void CString::operator +=( const CString & str )
{
	if ( str.m_Blob.Size() == 0 )
		return;
	if ( m_Blob.Size() > sizeof(TCHAR) )
		m_Blob.Assign( m_Blob.Data(), m_Blob.Size() - sizeof(TCHAR), (const TCHAR *)str, str.m_Blob.Size() );
	else
		*this = str;
#if _DEBUG
	this->text = *this;
#endif
}

int CString::Diff( const CString & other) const
{
	if ( this == &other )
		return 0;
	return _tcscmp( *this, other );
}

bool CString::operator < (const CString & other) const
{
	return _tcscmp( *this, other ) < 0;
}

bool CString::operator == (const CString & other) const
{
	return _tcscmp( *this, other ) == 0;
}

// extract string
CString::operator const TCHAR * () const
{
	const TCHAR * textPtr = (const TCHAR *)m_Blob.Data(); 
	if ( textPtr )
		return textPtr;
	else
		return _T("");
}

CString CString::operator + ( const CString & other ) const
{
	CString result = *this;
	result += other;
	return result;
}

CString operator + ( const TCHAR * s1, const CString & s2 ) 
{
	CString result;
	result.m_Blob.Assign( s1, _tcslen(s1)*sizeof s1[0], s2.m_Blob.Data(), s2.m_Blob.Size() );
	return result;
}

#if defined _WIN64 || defined _WIN32
//
// Serialize.cpp
//

void CSerialize::WriteBlob( const CBlob & blob )
{
	WriteDword( blob.Size() );
	WriteBytes( blob.Data(), blob.Size() );
}

void CSerialize::ReadBlob( CBlob & blob )
{
	DWORD	size;
	ReadDword( size );
	BYTE * pos = SkipBytes( size );
	blob.Assign( pos, size );
}


void CSerialize::WriteString( const WCHAR * ptr )
{
	if ( ptr )  {
		DWORD len = (DWORD)(wcslen( ptr ) + 1)*sizeof *ptr;
		WriteDword( len );
		WriteBytes( ptr, len );
	} else {
		WriteDword( 0 );
	}
}
void CSerialize::ReadString( WCHAR *& ptr )
{
	DWORD	len;
	ReadDword( len );
	if ( len )  {
		ptr = (WCHAR *)malloc( len );
		ReadBytes( ptr, len );
	} else {
		ptr = NULL;
	}
}
void CSerialize::AssignString( const WCHAR *& ptr )
{
	DWORD	len;
	ReadDword( len );
	if ( len )  {
		ptr = (WCHAR *)SkipBytes( len );
	} else {
		ptr = NULL;
	}
}

void CSerialize::WriteCString( const CString & string )
{
	if ( string.length() == 0 )  {
		WriteDword( 0 );
	} else {
		DWORD	len = (string.length() + 1)*sizeof(TCHAR);
		WriteDword( len );
		WriteBytes( (const WCHAR *)string, len );
	}
}
void CSerialize::ReadCString( CString & string )
{
	DWORD	len;
	ReadDword( len );
	if ( len == 0 )  {
		string = (const TCHAR *)NULL;
	} else {
		string = (WCHAR *)(m_Base + m_Offset);
		m_Offset += len;
	}
}

void CSerialize::WriteACL( const ACL * ptr )
{
	if ( ptr )  {
		WriteDword( ptr->AclSize );
		WriteBytes( ptr, ptr->AclSize );
	} else {
		WriteDword( 0 );
	}
}
void CSerialize::ReadACL( ACL *& ptr )
{
	DWORD	len;
	ReadDword( len );
	if ( len )  {
		ptr = (ACL *)malloc( len );
		ReadBytes( ptr, len );
	} else {
		ptr = NULL;
	}
}
void CSerialize::AssignACL( const ACL *& ptr )
{
	DWORD	len;
	ReadDword( len );
	if ( len )  {
		ptr = (ACL *)SkipBytes( len );
	} else {
		ptr = NULL;
	}
}

void CSerialize::WriteSID( const SID * ptr )
{
	if ( ptr )  {			
		DWORD sidLen = GetLengthSid( (PSID) ptr );
		WriteDword( sidLen );
		WriteBytes( ptr, sidLen );
	} else {
		WriteDword( 0 );
	}
}
void CSerialize::ReadSID( SID *& ptr )
{
	DWORD	len;
	ReadDword( len );
	if ( len )  {
		ptr = (SID *)malloc( len );
		ReadBytes( ptr, len );
	} else {
		ptr = NULL;
	}
}
void CSerialize::AssignSID( const SID *& ptr )
{
	DWORD	len;
	ReadDword( len );
	if ( len )  {
		ptr = (SID *)SkipBytes( len );
	} else {
		ptr = NULL;
	}
}

void CSerialize::WriteSecurityDescriptor( PSECURITY_DESCRIPTOR sd )
{
	if ( sd )  {
		DWORD	len = GetSecurityDescriptorLength( sd );
		WriteDword( len );
		WriteBytes( sd, len );
	} else {
		WriteDword( 0 );
	}
}
void CSerialize::ReadSecurityDescriptor( PSECURITY_DESCRIPTOR & sd )
{
	DWORD	len;
	ReadDword( len );
	if ( len )  {
		sd = (PSECURITY_DESCRIPTOR) malloc( len );
		ReadBytes( sd, len );
	} else {
		sd = NULL;
	}
}
#endif

//
// Resolver.cpp
//

CHostNameResolver	g_HostNameResolver;
CPortNameResolver	g_PortNameResolver;


CHostNameResolver::~CHostNameResolver()
{
	// Wait for all outstanding threads
	while ( m_ThreadCount > 0 )
		Sleep( 100 );
}


#if defined _WIN64 || defined _WIN32
void CHostNameResolver::Serialize( CSerialize & out ) const
{
	D_ASSERT( this->IsCritical() );
	out.WriteDword( (DWORD)m_AddrMap.size() );
	for ( ADDR_MAP::const_iterator pItem = m_AddrMap.begin(); pItem != m_AddrMap.end(); ++pItem ) {
		out.WriteBytes( pItem->first.addr, 16 );
		out.WriteCString( pItem->second );
	}
}

void CHostNameResolver::Deserialize( CSerialize & out )
{
	// Wait for all outstanding threads
	while ( m_ThreadCount > 0 )
		Sleep( 100 );

	CEnterCritical	crit( this );

	m_AddrMap.clear();
	DWORD size;
	out.ReadDword( size );
	for ( DWORD i = 0; i < size; ++i ) {
		ADDRESS	addr;
		CString	name;
		out.ReadBytes( &addr, 16 );
		out.ReadCString( name );
		m_AddrMap.insert( ADDR_MAP::value_type( addr, name ) );
	}
}
#endif

#if defined _WIN64 || defined _WIN32
unsigned __stdcall CHostNameResolver::AddThread( void * Context )
#elif defined __linux__
void *CHostNameResolver::AddThread( void * Context )
#endif
{
	LOOKUP_CONTEXT * context = (LOOKUP_CONTEXT *)Context;

	//
	// Handle the main request and then take any pending entries
	//
	while( context != NULL ) {

		CHostNameResolver * This = context->This;
		CString	*		pResult = context->Result;
		CString 		ipStr = IPAddressToString( context->Address.addr, context->IsV6 );
		int				ret;

		// resolve name
		char	hostname[ NI_MAXHOST ];
		hostname[0] = 0;
		if ( context->IsV6 ) {
			sockaddr_in6	address = { 0 };
			address.sin6_family		= AF_INET6;
			memcpy( &address.sin6_addr, context->Address.addr, 16 );
			ret = getnameinfo( (SOCKADDR *)&address, sizeof address, hostname, sizeof hostname, NULL, 0, NI_NAMEREQD );
		} else {
			sockaddr_in		address	= { 0 };
			address.sin_family		= PF_INET;
			memcpy( &address.sin_addr, context->Address.addr, 4 );
			memset( address.sin_zero, 0, sizeof address.sin_zero );
			ret = getnameinfo( (SOCKADDR *)&address, sizeof address, hostname, sizeof hostname, NULL, 0, NI_NAMEREQD );
		}

		CString	result;
		if ( ret == 0 && hostname[0] ) {
#if defined _WIN64 || defined _WIN32
			result = (_bstr_t)hostname;
#elif defined __linux__
			result = hostname;
#endif
		} else {
			//result = IPAddressToString( context->Address.addr, context->IsV6, -1 );
		}

		if( ret == 0 && result == ipStr ) {

			result = _T("");
		}

		delete context;
		context = NULL;

		// enter critical section to add to map and look for a new entry
		{
			CEnterCritical	crit( This );
			*pResult = result;

			if( This->m_AddrQueue.size() != 0 ) {

				context = This->m_AddrQueue.front();
				_ASSERT( context != NULL );
				This->m_AddrQueue.pop();
			}

			if( context == NULL ) {

				This->m_ThreadCount--;
			}
		}
	}
	return 0;
}

bool CHostNameResolver::AddAddress( const BYTE * addr, bool isV6 )
{
	// get copy of address
	ADDRESS			paddr;
	bool			createThread = true;
	if ( isV6 ) {
		memcpy( paddr.addr, addr, 16 );
	} else {
		memcpy( paddr.addr, addr, 4 );
		memset( paddr.addr+4, 0, 12 );
	}

	// see if we already have it
	CString	*	result = NULL;
	{
		CEnterCritical	crit( this );
		ADDR_MAP::const_iterator pItem = m_AddrMap.find( paddr );
		if ( pItem != m_AddrMap.end() ) {
			if ( pItem->second.length() == 0 ) {
				// currently being resolved by another thread
				return false;
			} else {
				// already resolved
				return true;
			}
		}

		// add an empty entry
		std::pair<ADDR_MAP::iterator,bool>	entry = m_AddrMap.insert( ADDR_MAP::value_type(paddr,_T("")) );
		// save address where result goes
		result = &entry.first->second;
	}

	// create a thread to resolve the name
	LOOKUP_CONTEXT * context = new LOOKUP_CONTEXT;
	if( context == NULL ) {

		return false;
	}
	context->This		= this;
	context->Address	= paddr;
	context->IsV6		= isV6;
	context->Result		= result;

	{
		CEnterCritical	crit( this );
		
		//
		// Limit the number of working threads
		//
		if( m_ThreadCount >= MAX_THREADS ) {

			//
			// Bail only if the queue is really large
			//
		    if( m_AddrQueue.size() >= MAX_QUEUE_SIZE ) {

				_ASSERT( !"Dropping Hostname requests" );
				return false;
			}

			m_AddrQueue.push( context );
		    createThread = false;
		} else {
			
			m_ThreadCount++;
		}
	}
	
	if( createThread ) {
		
#if defined _WIN64 || defined _WIN32
        UINT	id;
		HANDLE hThread = (HANDLE)_beginthreadex( NULL, 0, AddThread, context, 0, &id );

		if( hThread != INVALID_HANDLE_VALUE ) {
		
			CloseHandle( hThread );
		}
#elif defined __linux__
        pthread_t hThread;
        int tRet = pthread_create( &hThread, NULL, AddThread, (void *)context );
        if (tRet == 0) {
            pthread_join( hThread, NULL );
        }
#endif
	}

	return false;
}


CString CHostNameResolver::ResolveAddress( const BYTE * addr, bool isV6 )
{
	ADDRESS			paddr;
	if ( isV6 ) {
		memcpy( paddr.addr, addr, 16 );
	} else {
		memcpy( paddr.addr, addr, 4 );
		memset( paddr.addr+4, 0, 12 );
	}

	{
		CEnterCritical	crit( this );
		ADDR_MAP::const_iterator pItem = m_AddrMap.find( paddr );
		if ( pItem != m_AddrMap.end() ) {
			// item found
			if ( pItem->second.length() ) {
				// item is resolved
				return pItem->second;
			} else {
				// item hasn't been resolved yet
			}
		}
	}
	// currently being resolved, so use numeric form instead
	return _T(""); //IPAddressToString( addr, isV6, -1 );
}



CPortNameResolver::~CPortNameResolver()
{
	// Wait for all outstanding threads
	while ( m_ThreadCount > 0 )
		Sleep( 100 );
}

#if defined _WIN64 || defined _WIN32
void CPortNameResolver::Serialize( CSerialize & out ) const
{
	CEnterCritical	crit( this );
	out.WriteDword( (DWORD)m_PortMap.size() );
	for ( PORT_MAP::const_iterator pItem = m_PortMap.begin(); pItem != m_PortMap.end(); ++pItem ) {
		out.WriteDword( pItem->first );
		out.WriteCString( pItem->second );
	}
}

void CPortNameResolver::Deserialize( CSerialize & out )
{
	// Wait for all outstanding threads
	while ( m_ThreadCount > 0 )
		Sleep( 100 );

	CEnterCritical	crit( this );
	m_PortMap.clear();
	DWORD size;
	out.ReadDword( size );
	for ( DWORD i = 0; i < size; ++i ) {
		DWORD	port;
		CString	name;
		out.ReadDword( port );
		out.ReadCString( name );
		m_PortMap.insert( PORT_MAP::value_type( port, name ) );
	}
}
#endif

#if defined _WIN64 || defined _WIN32
unsigned __stdcall CPortNameResolver::AddThread( void * Context )
#elif defined __linux__
void *CPortNameResolver::AddThread( void * Context )
#endif
{
	LOOKUP_CONTEXT * context = (LOOKUP_CONTEXT *)Context;

	while( context != NULL ) {

		CString *	pResult = context->Result;
		CPortNameResolver * 	This = context->This;
		char	portname[ NI_MAXSERV ];
		portname[0] = 0;
		if ( context->IsTCP ) {
			sockaddr_in6	address	= { 0 };
			address.sin6_family		= AF_INET6;
			address.sin6_port		= htons(context->Port);
			getnameinfo( (SOCKADDR *)&address, sizeof address, NULL, 0, portname, sizeof portname, context->IsTCP ? 0 : NI_DGRAM );
		} else {
			sockaddr_in		address	= { 0 };
			address.sin_family		= PF_INET;
			address.sin_port		= htons(context->Port);
			getnameinfo( (SOCKADDR *)&address, sizeof address, NULL, 0, portname, sizeof portname, context->IsTCP ? 0 : NI_DGRAM );
		}

		CString result;
		if ( portname[0] ) {
#if defined _WIN64 || defined _WIN32
			result = (_bstr_t)portname;
#elif defined __linux__
			result = portname;
#endif
		} else {
			//result = IntToString( context->Port );
		}

		if( IntToString( context->Port ) == result ) {

			result = _T("");
		}

		delete context;
		context = NULL;

		// enter critical section to add to map and get a new entry
		{
			CEnterCritical	crit( This );
			*pResult = result;

			if( This->m_PortQueue.size() != 0 ) {

				context = This->m_PortQueue.front();
				_ASSERT( context != NULL );
				This->m_PortQueue.pop();
			}

			if( context == NULL ) {

				This->m_ThreadCount--;
			}
		}
	}
	return 0;
}

bool CPortNameResolver::AddPort( WORD port, bool isTCP )
{
	//
	// According to the official service name <-> port number list
	// The highest official is 49151, because we get flooded by request above this number, we discard them
	// Link: http://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.txt
	//
	if( port > 49200 ) {

		return false;
	}
	
	DWORD	pport = port | isTCP << 16;
	bool	createThread = true;

	// See if we already have it
	CString * result = NULL;
	{
		CEnterCritical	crit( this );
		PORT_MAP::const_iterator pItem = m_PortMap.find( pport );
		if ( pItem != m_PortMap.end() ) {
			if ( pItem->second.length() == 0 ) {
				// currently being resolved by another thread
				return false;
			} else {
				// already resolved
				return true;
			}
		}

		// add an empty entry
		std::pair<PORT_MAP::iterator,bool>	entry = m_PortMap.insert( PORT_MAP::value_type(pport,_T("")) );
		// save address where result goes
		result = &entry.first->second;
	}

	// create a thread to resolve the name
	LOOKUP_CONTEXT * context = new LOOKUP_CONTEXT;
	if( context == NULL ) {

		return false;
	}
	context->This		= this;
	context->Port		= port;
	context->IsTCP		= isTCP;
	context->Result		= result;

	{
		CEnterCritical	crit( this );
		
		//
		// Limit the number of working threads
		//
		if( m_ThreadCount >= MAX_THREADS ) {

			//
			// Bail only if the queue is really large
			//
			if( m_PortQueue.size() >= MAX_QUEUE_SIZE ) {

				_ASSERT( !"Dropping PORT requests" );
				return false;
			}

			m_PortQueue.push( context );
		    createThread = false;
		} else {
			
			m_ThreadCount++;
		}
	}

	if( createThread ) {
		
#if defined _WIN64 || defined _WIN32
        UINT	id;
		HANDLE hThread = (HANDLE)_beginthreadex( NULL, 0, AddThread, context, 0, &id );

		if( hThread != INVALID_HANDLE_VALUE ) {
		
			CloseHandle( hThread );
		}
#elif defined __linux__
        pthread_t hThread;
        int tRet = pthread_create( &hThread, NULL, AddThread, (void *)context );
        if (tRet == 0) {
            pthread_join( hThread, NULL );
        }
#endif
	}

	return false;
}

CString CPortNameResolver::ResolvePort( WORD port, bool isTCP )
{		
	DWORD	pport = port | isTCP << 16;

	{
		CEnterCritical	crit( this );
		PORT_MAP::const_iterator pItem = m_PortMap.find( pport );
		if ( pItem != m_PortMap.end() ) {
			if ( pItem->second.length() ) {
				// item is resolved
				return pItem->second;
			} else {
				// item hasn't been resolved yet
			}
		}
	}
	// currently being resolved, so use numeric form instead
	return _T(""); //IntToString( port );
}

//
// Misc.pp
//

//----------------------------------------------------------------------
//
// IPAddressToString
//
//----------------------------------------------------------------------
CString IPAddressToString( const BYTE * addr, bool isV6 )
{
	TCHAR	name[ 60 ];
	if ( isV6 )  {
		const WORD	* ipv6format = (WORD *)addr;
		_stprintf_s( name, _countof(name), _T("%x:%x:%x:%x:%x:%x:%x:%x"), 
				htons( ipv6format[0]),
				htons( ipv6format[1]),
				htons( ipv6format[2]),
				htons( ipv6format[3]),
				htons( ipv6format[4]),
				htons( ipv6format[5]),
				htons( ipv6format[6]),
				htons( ipv6format[7]));
	} else {
		_stprintf_s( name, _countof(name), _T("%d.%d.%d.%d"), addr[0], addr[1], addr[2], addr[3] );
	}

	return name;
}


//----------------------------------------------------------------------
//
// IPAddressToHostName
//
//----------------------------------------------------------------------
CString	IPAddressToHostName( const BYTE * addr, bool isV6, WORD port, bool isTCP )
{
	CString hostname = g_HostNameResolver.ResolveAddress( addr, isV6 );
	CString portname = g_PortNameResolver.ResolvePort( port, isTCP );
	return hostname + _T(":") + portname;
}

//----------------------------------------------------------------------
//
// IntToString
//
//----------------------------------------------------------------------
CString IntToString( LONGLONG value )
{
	TCHAR text[ 30 ];
#if defined _WIN64 || defined _WIN32
	_stprintf_s( text, _countof( text ),_T("%I64d"), value );
#elif defined __linux__
	_stprintf_s( text, _countof( text ),_T("%" PRId64), value );
#endif
	return text;
}

#if defined __linux__
//----------------------------------------------------------------------
//
// LookupAccountNameFromPID
//
//----------------------------------------------------------------------
CString LookupAccountNameFromPID(
    _In_ DWORD ProcessId,
    _In_ PLARGE_INTEGER Timestamp
    )
{
    CString                     retValue;
    char                        buf[128];
    PPROCESS_CACHE_INFORMATION  cache;
    char                        pathFile[32];
    FILE                        *fp = NULL;
    unsigned int                uid = 0;
    bool                        gotUid = false;

    ProcessCache::Instance().LockCache();
    cache = ProcessCache::Instance().ProcessGet( ProcessId, Timestamp, NULL );
    if (cache != NULL) {
        uid = cache->data->m_AuthenticationId.LowPart;
        gotUid = true;
    }
    ProcessCache::Instance().UnlockCache();

    if (!gotUid) {
        snprintf( pathFile, 32, "/proc/%d/loginuid", ProcessId );
        fp = fopen( pathFile, "r" );
        if (fp != NULL) {
            fscanf( fp, "%d", &uid );
            fclose( fp );
        }
    }
    TranslateSid( (PSID)&uid, buf, 128 );
    retValue = buf;
    return retValue;
}
#endif

