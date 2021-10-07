/*
    SysmonCommon

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/


//======================================================================
//
// NetworkCommon.cpp
//
// TCP/UDP ETW event consumer. 
//
//======================================================================

#if defined __linux__
#include "linuxTypes.h"
#include "ioctlcmd.h"
#endif

#include "networkCommon.h"

#if defined __linux__
#define _bstr_t void *
#endif

BOOLEAN		g_DnsLookup = TRUE;

#if defined __linux__
extern "C"
#endif

bool CreateNetworkEvent( DWORD processId, DWORD threadId, EVENT_TYPE_NETWORK type, bool isTcp,
						LARGE_INTEGER timestamp, ULONGLONG duration, DWORD length,
						bool srcIsIpV4, const BYTE * srcAddr, WORD srcPort,
						bool dstIsIpV4, const BYTE * dstAddr, WORD dstPort,
						const void * const stackEntries[], DWORD stackCnt,
						const _bstr_t & details )
{
	CString srcAddrStr = IPAddressToString( srcAddr, !srcIsIpV4 );
	CString dstAddrStr = IPAddressToString( dstAddr, !dstIsIpV4 );

	ULONG isInitiated = (type == EVENT_TYPE_NETWORK_CONNECT || type == EVENT_TYPE_NETWORK_SEND ? 1 : 0);
	CString	username = LookupAccountNameFromPID( processId, &timestamp );

	CString srcHostStr = _T( "" );
	CString dstHostStr = _T( "" );
	CString srcPortname = _T( "" );
	CString dstPortname = _T( "" );
	if( g_DnsLookup ) {

		srcHostStr = g_HostNameResolver.ResolveAddress( srcAddr, !srcIsIpV4 );
		dstHostStr = g_HostNameResolver.ResolveAddress( dstAddr, !dstIsIpV4 );
		srcPortname = g_PortNameResolver.ResolvePort( srcPort, isTcp );
		dstPortname = g_PortNameResolver.ResolvePort( dstPort, isTcp );
	}
	NetworkEvent( &timestamp,
				  processId,
				  username,
				  isTcp,
				  isInitiated,
				  !srcIsIpV4 ? 1 : 0,
				  srcAddrStr,
				  srcHostStr,
				  srcPort,
				  srcPortname,
				  !dstIsIpV4 ? 1 : 0,
				  dstAddrStr,
				  dstHostStr,
				  dstPort,
				  dstPortname );

	return true;
}


