/**
 * This file has no copyright assigned and is placed in the Public Domain.
 * This file is part of the mingw-w64 runtime package.
 * No warranty is given; refer to the file DISCLAIMER.PD within this package.
 */

#ifndef _WINSOCK2API1_
#define _WINSOCK2API1_

#include <_mingw_unicode.h>

#ifndef _WINSOCKAPI_
#define _WINSOCKAPI_
#else
#warning Please include winsock2.h before windows.h
#endif

#ifndef _INC_WINDOWS
#include <windows.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define FROM_PROTOCOL_INFO (-1) 

#define MAX_PROTOCOL_CHAIN 7

#define BASE_PROTOCOL 1
#define LAYERED_PROTOCOL 0

#define INVALID_SOCKET	(SOCKET)(~0)
#define SOCKET_ERROR	(-1) 

typedef UINT_PTR	SOCKET; 
typedef unsigned int GROUP; 
  
typedef struct _WSAPROTOCOLCHAIN {
	int ChainLen;

	DWORD ChainEntries[MAX_PROTOCOL_CHAIN];
} WSAPROTOCOLCHAIN,*LPWSAPROTOCOLCHAIN; 
  
#define WSAPROTOCOL_LEN 255

  typedef struct _WSAPROTOCOL_INFOA {
    DWORD dwServiceFlags1;
    DWORD dwServiceFlags2;
    DWORD dwServiceFlags3;
    DWORD dwServiceFlags4;
    DWORD dwProviderFlags;
    GUID ProviderId;
    DWORD dwCatalogEntryId;
    WSAPROTOCOLCHAIN ProtocolChain;
    int iVersion;
    int iAddressFamily;
    int iMaxSockAddr;
    int iMinSockAddr;
    int iSocketType;
    int iProtocol;
    int iProtocolMaxOffset;
    int iNetworkByteOrder;
    int iSecurityScheme;
    DWORD dwMessageSize;
    DWORD dwProviderReserved;
    CHAR szProtocol[WSAPROTOCOL_LEN+1];
  } WSAPROTOCOL_INFOA,*LPWSAPROTOCOL_INFOA;

  typedef struct _WSAPROTOCOL_INFOW {
    DWORD dwServiceFlags1;
    DWORD dwServiceFlags2;
    DWORD dwServiceFlags3;
    DWORD dwServiceFlags4;
    DWORD dwProviderFlags;
    GUID ProviderId;
    DWORD dwCatalogEntryId;
    WSAPROTOCOLCHAIN ProtocolChain;
    int iVersion;
    int iAddressFamily;
    int iMaxSockAddr;
    int iMinSockAddr;
    int iSocketType;
    int iProtocol;
    int iProtocolMaxOffset;
    int iNetworkByteOrder;
    int iSecurityScheme;
    DWORD dwMessageSize;
    DWORD dwProviderReserved;
    WCHAR szProtocol[WSAPROTOCOL_LEN+1];
  } WSAPROTOCOL_INFOW,*LPWSAPROTOCOL_INFOW;

  __MINGW_TYPEDEF_AW(WSAPROTOCOL_INFO)
  __MINGW_TYPEDEF_AW(LPWSAPROTOCOL_INFO)

#ifndef WINSOCK_API_LINKAGE
#ifdef  DECLSPEC_IMPORT
#define WINSOCK_API_LINKAGE	DECLSPEC_IMPORT
#else
#define WINSOCK_API_LINKAGE
#endif
#endif /* WINSOCK_API_LINKAGE */
#define WSAAPI			WINAPI
 
#define WSASocket __MINGW_NAME_AW(WSASocket) 
WINSOCK_API_LINKAGE SOCKET WSAAPI WSASocketA(int af,int type,int protocol,LPWSAPROTOCOL_INFOA lpProtocolInfo,GROUP g,DWORD dwFlags);
WINSOCK_API_LINKAGE SOCKET WSAAPI WSASocketW(int af,int type,int protocol,LPWSAPROTOCOL_INFOW lpProtocolInfo,GROUP g,DWORD dwFlags); 

#define WSADuplicateSocket __MINGW_NAME_AW(WSADuplicateSocket) 
WINSOCK_API_LINKAGE int WSAAPI WSADuplicateSocketA(SOCKET s,DWORD dwProcessId,LPWSAPROTOCOL_INFOA lpProtocolInfo);
WINSOCK_API_LINKAGE int WSAAPI WSADuplicateSocketW(SOCKET s,DWORD dwProcessId,LPWSAPROTOCOL_INFOW lpProtocolInfo); 

WINSOCK_API_LINKAGE int WSAAPI WSAGetLastError(void); 

#ifdef __cplusplus
}
#endif

#endif /* _WINSOCK2API_ */
