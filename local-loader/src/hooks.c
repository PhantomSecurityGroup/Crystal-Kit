#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winldap.h>
#include <wininet.h>
#include <iphlpapi.h>
#include <combaseapi.h>
#define SECURITY_WIN32
#include <security.h>
#include <ntsecapi.h>
#include "tcg.h"
#include "memory.h"
#include "spoof.h"


DECLSPEC_IMPORT HINTERNET WINAPI WININET$InternetConnectA    ( HINTERNET, LPCSTR, INTERNET_PORT, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR );
DECLSPEC_IMPORT HINTERNET WINAPI WININET$InternetOpenA       ( LPCSTR, DWORD, LPCSTR, LPCSTR, DWORD );
DECLSPEC_IMPORT BOOL      WINAPI KERNEL32$CloseHandle        ( HANDLE );
DECLSPEC_IMPORT HANDLE    WINAPI KERNEL32$CreateFileMappingA ( HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR );
DECLSPEC_IMPORT BOOL      WINAPI KERNEL32$CreateProcessA     ( LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION );
DECLSPEC_IMPORT HANDLE    WINAPI KERNEL32$CreateRemoteThread ( HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD );
DECLSPEC_IMPORT HANDLE    WINAPI KERNEL32$CreateThread       ( LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD );
DECLSPEC_IMPORT BOOL      WINAPI KERNEL32$DuplicateHandle    ( HANDLE, HANDLE, HANDLE, LPHANDLE, DWORD, BOOL, DWORD );
DECLSPEC_IMPORT BOOL      WINAPI KERNEL32$GetThreadContext   ( HANDLE, LPCONTEXT );
DECLSPEC_IMPORT HMODULE   WINAPI KERNEL32$LoadLibraryA       ( LPCSTR );
DECLSPEC_IMPORT LPVOID    WINAPI KERNEL32$MapViewOfFile      ( HANDLE, DWORD, DWORD, DWORD, SIZE_T );
DECLSPEC_IMPORT HANDLE    WINAPI KERNEL32$OpenProcess        ( DWORD, BOOL, DWORD );
DECLSPEC_IMPORT HANDLE    WINAPI KERNEL32$OpenThread         ( DWORD, BOOL, DWORD );
DECLSPEC_IMPORT BOOL      WINAPI KERNEL32$ReadProcessMemory  ( HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T * );
DECLSPEC_IMPORT DWORD     WINAPI KERNEL32$ResumeThread       ( HANDLE );
DECLSPEC_IMPORT VOID      WINAPI KERNEL32$RtlCaptureContext  ( PCONTEXT );
DECLSPEC_IMPORT BOOL      WINAPI KERNEL32$SetThreadContext   ( HANDLE, const CONTEXT * );
DECLSPEC_IMPORT BOOL      WINAPI KERNEL32$UnmapViewOfFile    ( LPCVOID );
DECLSPEC_IMPORT LPVOID    WINAPI KERNEL32$VirtualAlloc       ( LPVOID, SIZE_T, DWORD, DWORD );
DECLSPEC_IMPORT LPVOID    WINAPI KERNEL32$VirtualAllocEx     ( HANDLE, LPVOID, SIZE_T, DWORD, DWORD );
DECLSPEC_IMPORT BOOL      WINAPI KERNEL32$VirtualFree        ( LPVOID, SIZE_T, DWORD );
DECLSPEC_IMPORT BOOL      WINAPI KERNEL32$VirtualProtect     ( LPVOID, SIZE_T, DWORD, PDWORD );
DECLSPEC_IMPORT BOOL      WINAPI KERNEL32$VirtualProtectEx   ( HANDLE, LPVOID, SIZE_T, DWORD, PDWORD );
DECLSPEC_IMPORT SIZE_T    WINAPI KERNEL32$VirtualQuery       ( LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T );
DECLSPEC_IMPORT BOOL      WINAPI KERNEL32$WriteProcessMemory ( HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T * );
DECLSPEC_IMPORT HRESULT   WINAPI OLE32$CoCreateInstance      ( REFCLSID, LPUNKNOWN, DWORD, REFIID, LPVOID * );
DECLSPEC_IMPORT ULONG     NTAPI  NTDLL$NtContinue            ( CONTEXT *, BOOLEAN );

// Custom added hooks
DECLSPEC_IMPORT int             WSAAPI WS2_32$bind ( SOCKET, const struct sockaddr *, int );
DECLSPEC_IMPORT int             WSAAPI WS2_32$connect ( SOCKET, const struct sockaddr *, int );
DECLSPEC_IMPORT int             WSAAPI WS2_32$getaddrinfo ( const char *, const char *, const struct addrinfo *, struct addrinfo ** );
DECLSPEC_IMPORT int             WSAAPI WS2_32$send ( SOCKET, const char *, int, int );
DECLSPEC_IMPORT SOCKET          WSAAPI WS2_32$socket ( int, int, int );
DECLSPEC_IMPORT BOOL            WINAPI ADVAPI32$OpenProcessToken ( HANDLE, DWORD, PHANDLE );
DECLSPEC_IMPORT BOOL            WINAPI ADVAPI32$GetTokenInformation ( HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD );
DECLSPEC_IMPORT DWORD           WINAPI KERNEL32$WaitForSingleObject ( HANDLE, DWORD );
DECLSPEC_IMPORT HANDLE          WINAPI KERNEL32$GetCurrentThread ( VOID );
DECLSPEC_IMPORT HANDLE          WINAPI KERNEL32$GetCurrentProcess ( VOID );
DECLSPEC_IMPORT HINSTANCE       WINAPI SHELL32$ShellExecuteA ( HWND, LPCSTR, LPCSTR, LPCSTR, LPCSTR, INT );
DECLSPEC_IMPORT PLDAPSearch     LDAPAPI WLDAP32$ldap_search_init_pageA ( PLDAP, const PSTR, ULONG, const PSTR, PZPSTR, ULONG, PLDAPControlA *, PLDAPControlA *, ULONG, ULONG, PLDAPSortKeyA * );
DECLSPEC_IMPORT ULONG LDAPAPI   WLDAP32$ldap_bind_s ( LDAP *, const PSTR, const PCHAR, ULONG );
DECLSPEC_IMPORT LDAP *LDAPAPI   WLDAP32$ldap_init ( PSTR, ULONG );

// Have not been implemented as functions yet and have not yet #include the right header for types
DECLSPEC_IMPORT NTSTATUS        NTAPI SECUR32$LsaRegisterLogonProcess ( PLSA_STRING, PHANDLE, PLSA_OPERATIONAL_MODE );
DECLSPEC_IMPORT NTSTATUS        NTAPI SECUR32$LsaConnectUntrusted ( PHANDLE );


HINTERNET WINAPI _InternetOpenA ( LPCSTR lpszAgent, DWORD dwAccessType, LPCSTR lpszProxy, LPCSTR lpszProxyBypass, DWORD dwFlags )
{
    FUNCTION_CALL call = { 0 };

    call.ptr        = ( PVOID ) ( WININET$InternetOpenA );
    call.argc       = 5;
    call.args [ 0 ] = spoof_arg ( lpszAgent );
    call.args [ 1 ] = spoof_arg ( dwAccessType );
    call.args [ 2 ] = spoof_arg ( lpszProxy );
    call.args [ 3 ] = spoof_arg ( lpszProxyBypass );
    call.args [ 4 ] = spoof_arg ( dwFlags );

    return ( HINTERNET ) spoof_call ( &call );
}

HINTERNET WINAPI _InternetConnectA ( HINTERNET hInternet, LPCSTR lpszServerName, INTERNET_PORT nServerPort, LPCSTR lpszUserName, LPCSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext )
{
    FUNCTION_CALL call = { 0 };

    call.ptr        = ( PVOID ) ( WININET$InternetConnectA );
    call.argc       = 8;
    call.args [ 0 ] = spoof_arg ( hInternet );
    call.args [ 1 ] = spoof_arg ( lpszServerName );
    call.args [ 2 ] = spoof_arg ( nServerPort );
    call.args [ 3 ] = spoof_arg ( lpszUserName );
    call.args [ 4 ] = spoof_arg ( lpszPassword );
    call.args [ 5 ] = spoof_arg ( dwService );
    call.args [ 6 ] = spoof_arg ( dwFlags );
    call.args [ 7 ] = spoof_arg ( dwContext );

    return ( HINTERNET ) spoof_call ( &call );
}

BOOL WINAPI _CloseHandle ( HANDLE hObject )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID ) ( KERNEL32$CloseHandle );
    call.argc = 1;
    
    call.args [ 0 ] = spoof_arg ( hObject );

    return ( BOOL ) spoof_call ( &call );
}

HANDLE WINAPI _CreateFileMappingA ( HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCSTR lpName )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID ) ( KERNEL32$CreateFileMappingA );
    call.argc = 6;

    call.args [ 0 ] = spoof_arg ( hFile );
    call.args [ 1 ] = spoof_arg ( lpFileMappingAttributes );
    call.args [ 2 ] = spoof_arg ( flProtect );
    call.args [ 3 ] = spoof_arg ( dwMaximumSizeHigh );
    call.args [ 4 ] = spoof_arg ( dwMaximumSizeLow );
    call.args [ 5 ] = spoof_arg ( lpName );

    return ( HANDLE ) spoof_call ( &call );
}

BOOL _CreateProcessA ( LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID ) ( KERNEL32$CreateProcessA );
    call.argc = 10;

    call.args [ 0 ] = spoof_arg ( lpApplicationName );
    call.args [ 1 ] = spoof_arg ( lpCommandLine );
    call.args [ 2 ] = spoof_arg ( lpProcessAttributes );
    call.args [ 3 ] = spoof_arg ( lpThreadAttributes );
    call.args [ 4 ] = spoof_arg ( bInheritHandles );
    call.args [ 5 ] = spoof_arg ( dwCreationFlags );
    call.args [ 6 ] = spoof_arg ( lpEnvironment );
    call.args [ 7 ] = spoof_arg ( lpCurrentDirectory );
    call.args [ 8 ] = spoof_arg ( lpStartupInfo );
    call.args [ 9 ] = spoof_arg ( lpProcessInformation );

    return ( BOOL ) spoof_call ( &call );
}

HANDLE WINAPI _CreateRemoteThread ( HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID ) ( KERNEL32$CreateRemoteThread );
    call.argc = 7;

    call.args [ 0 ] = spoof_arg ( hProcess );
    call.args [ 1 ] = spoof_arg ( lpThreadAttributes );
    call.args [ 2 ] = spoof_arg ( dwStackSize );
    call.args [ 3 ] = spoof_arg ( lpStartAddress );
    call.args [ 4 ] = spoof_arg ( lpParameter );
    call.args [ 5 ] = spoof_arg ( dwCreationFlags );
    call.args [ 6 ] = spoof_arg ( lpThreadId );

    return ( HANDLE ) spoof_call ( &call );
}

HANDLE WINAPI _CreateThread ( LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID ) ( KERNEL32$CreateThread );
    call.argc = 6;
    
    call.args [ 0 ] = spoof_arg ( lpThreadAttributes );
    call.args [ 1 ] = spoof_arg ( dwStackSize );
    call.args [ 2 ] = spoof_arg ( lpStartAddress );
    call.args [ 3 ] = spoof_arg ( lpParameter );
    call.args [ 4 ] = spoof_arg ( dwCreationFlags );
    call.args [ 5 ] = spoof_arg ( lpThreadId );

    return ( HANDLE ) spoof_call ( &call );
}

HRESULT WINAPI _CoCreateInstance ( REFCLSID rclsid, LPUNKNOWN pUnkOuter, DWORD dwClsContext, REFIID riid, LPVOID * ppv )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID ) ( OLE32$CoCreateInstance );
    call.argc = 5;
    
    call.args [ 0 ] = spoof_arg ( rclsid );
    call.args [ 1 ] = spoof_arg ( pUnkOuter );
    call.args [ 2 ] = spoof_arg ( dwClsContext );
    call.args [ 3 ] = spoof_arg ( riid );
    call.args [ 4 ] = spoof_arg ( ppv );

    return ( HRESULT ) spoof_call ( &call );
}

BOOL WINAPI _DuplicateHandle ( HANDLE hSourceProcessHandle, HANDLE hSourceHandle, HANDLE hTargetProcessHandle, LPHANDLE lpTargetHandle, DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwOptions )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID ) ( KERNEL32$DuplicateHandle );
    call.argc = 7;
    
    call.args [ 0 ] = spoof_arg ( hSourceProcessHandle );
    call.args [ 1 ] = spoof_arg ( hSourceHandle );
    call.args [ 2 ] = spoof_arg ( hTargetProcessHandle );
    call.args [ 3 ] = spoof_arg ( lpTargetHandle );
    call.args [ 4 ] = spoof_arg ( dwDesiredAccess );
    call.args [ 5 ] = spoof_arg ( bInheritHandle );
    call.args [ 6 ] = spoof_arg ( dwOptions );

    return ( BOOL ) spoof_call ( &call );
}

HMODULE WINAPI _LoadLibraryA ( LPCSTR lpLibFileName )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID ) ( KERNEL32$LoadLibraryA );
    call.argc = 1;
    
    call.args [ 0 ] = spoof_arg ( lpLibFileName );

    return ( HMODULE ) spoof_call ( &call );
}

BOOL WINAPI _GetThreadContext ( HANDLE hThread, LPCONTEXT lpContext )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID ) ( KERNEL32$GetThreadContext );
    call.argc = 2;
    
    call.args [ 0 ] = spoof_arg ( hThread );
    call.args [ 1 ] = spoof_arg ( lpContext );

    return ( BOOL ) spoof_call ( &call );
}

LPVOID WINAPI _MapViewOfFile ( HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID ) ( KERNEL32$MapViewOfFile );
    call.argc = 5;
    
    call.args [ 0 ] = spoof_arg ( hFileMappingObject );
    call.args [ 1 ] = spoof_arg ( dwDesiredAccess );
    call.args [ 2 ] = spoof_arg ( dwFileOffsetHigh );
    call.args [ 3 ] = spoof_arg ( dwFileOffsetLow );
    call.args [ 4 ] = spoof_arg ( dwNumberOfBytesToMap );

    return ( LPVOID ) spoof_call ( &call );
}

HANDLE WINAPI _OpenProcess ( DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID ) ( KERNEL32$OpenProcess );
    call.argc = 3;
    
    call.args [ 0 ] = spoof_arg ( dwDesiredAccess );
    call.args [ 1 ] = spoof_arg ( bInheritHandle );
    call.args [ 2 ] = spoof_arg ( dwProcessId );

    return ( HANDLE ) spoof_call ( &call );
}

HANDLE WINAPI _OpenThread ( DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID ) ( KERNEL32$OpenThread );
    call.argc = 3;
    
    call.args [ 0 ] = spoof_arg ( dwDesiredAccess );
    call.args [ 1 ] = spoof_arg ( bInheritHandle );
    call.args [ 2 ] = spoof_arg ( dwThreadId );

    return ( HANDLE ) spoof_call ( &call );
}

BOOL WINAPI _ReadProcessMemory ( HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T * lpNumberOfBytesRead )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID ) ( KERNEL32$ReadProcessMemory );
    call.argc = 5;
    
    call.args [ 0 ] = spoof_arg ( hProcess );
    call.args [ 1 ] = spoof_arg ( lpBaseAddress );
    call.args [ 2 ] = spoof_arg ( lpBuffer );
    call.args [ 3 ] = spoof_arg ( nSize );
    call.args [ 4 ] = spoof_arg ( lpNumberOfBytesRead );

    return ( BOOL ) spoof_call ( &call );
}

DWORD WINAPI _ResumeThread ( HANDLE hThread )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID ) ( KERNEL32$ResumeThread );
    call.argc = 1;
    
    call.args [ 0 ] = spoof_arg ( hThread );

    return ( DWORD ) spoof_call ( &call );
}

BOOL WINAPI _SetThreadContext ( HANDLE hThread, const CONTEXT * lpContext )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID ) ( KERNEL32$SetThreadContext );
    call.argc = 2;
    
    call.args [ 0 ] = spoof_arg ( hThread );
    call.args [ 1 ] = spoof_arg ( lpContext );

    return ( BOOL ) spoof_call ( &call );
}

BOOL WINAPI _UnmapViewOfFile ( LPCVOID lpBaseAddress )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID ) ( KERNEL32$UnmapViewOfFile );
    call.argc = 1;
    
    call.args [ 0 ] = spoof_arg ( lpBaseAddress );

    return ( BOOL ) spoof_call ( &call );
}

LPVOID WINAPI _VirtualAlloc ( LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID ) ( KERNEL32$VirtualAlloc );
    call.argc = 4;
    
    call.args [ 0 ] = spoof_arg ( lpAddress );
    call.args [ 1 ] = spoof_arg ( dwSize );
    call.args [ 2 ] = spoof_arg ( flAllocationType );
    call.args [ 3 ] = spoof_arg ( flProtect );

    return ( LPVOID ) spoof_call ( &call );
}

LPVOID WINAPI _VirtualAllocEx ( HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID ) ( KERNEL32$VirtualAllocEx );
    call.argc = 5;
    
    call.args [ 0 ] = spoof_arg ( hProcess );
    call.args [ 1 ] = spoof_arg ( lpAddress );
    call.args [ 2 ] = spoof_arg ( dwSize );
    call.args [ 3 ] = spoof_arg ( flAllocationType );
    call.args [ 4 ] = spoof_arg ( flProtect );

    return ( LPVOID ) spoof_call ( &call );
}

BOOL WINAPI _VirtualFree ( LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID ) ( KERNEL32$VirtualFree );
    call.argc = 3;
    
    call.args [ 0 ] = spoof_arg ( lpAddress );
    call.args [ 1 ] = spoof_arg ( dwSize );
    call.args [ 2 ] = spoof_arg ( dwFreeType );

    return ( BOOL ) spoof_call ( &call );
}

BOOL WINAPI _VirtualProtect ( LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID ) ( KERNEL32$VirtualProtect );
    call.argc = 4;
    
    call.args [ 0 ] = spoof_arg ( lpAddress );
    call.args [ 1 ] = spoof_arg ( dwSize );
    call.args [ 2 ] = spoof_arg ( flNewProtect );
    call.args [ 3 ] = spoof_arg ( lpflOldProtect );

    return ( BOOL ) spoof_call ( &call );
}

BOOL WINAPI _VirtualProtectEx ( HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID ) ( KERNEL32$VirtualProtectEx );
    call.argc = 5;
    
    call.args [ 0 ] = spoof_arg ( hProcess );
    call.args [ 1 ] = spoof_arg ( lpAddress );
    call.args [ 2 ] = spoof_arg ( dwSize );
    call.args [ 3 ] = spoof_arg ( flNewProtect );
    call.args [ 4 ] = spoof_arg ( lpflOldProtect );

    return ( BOOL ) spoof_call ( &call );
}

SIZE_T WINAPI _VirtualQuery ( LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID ) ( KERNEL32$VirtualQuery );
    call.argc = 3;
    
    call.args [ 0 ] = spoof_arg ( lpAddress );
    call.args [ 1 ] = spoof_arg ( lpBuffer );
    call.args [ 2 ] = spoof_arg ( dwLength );

    return ( SIZE_T ) spoof_call ( &call );
}

BOOL WINAPI _WriteProcessMemory ( HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T * lpNumberOfBytesWritten )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID ) ( KERNEL32$WriteProcessMemory );
    call.argc = 5;
    
    call.args [ 0 ] = spoof_arg ( hProcess );
    call.args [ 1 ] = spoof_arg ( lpBaseAddress );
    call.args [ 2 ] = spoof_arg ( lpBuffer );
    call.args [ 3 ] = spoof_arg ( nSize );
    call.args [ 4 ] = spoof_arg ( lpNumberOfBytesWritten );

    return ( BOOL ) spoof_call ( &call );
}

ULONG LDAPAPI _ldap_bind_s ( LDAP * ld, const PSTR dn, const PCHAR cred, ULONG method )
{
    FUNCTION_CALL call = { 0 };

    call.ptr        = ( PVOID ) ( WLDAP32$ldap_bind_s );
    call.argc       = 4;
    call.args [ 0 ] = spoof_arg ( ld );
    call.args [ 1 ] = spoof_arg ( dn );
    call.args [ 2 ] = spoof_arg ( cred );
    call.args [ 3 ] = spoof_arg ( method );

    return ( ULONG ) spoof_call ( &call );
}

LDAP * LDAPAPI _ldap_init ( PSTR HostName, ULONG PortNumber )
{
    FUNCTION_CALL call = { 0 };

    call.ptr        = ( PVOID ) WLDAP32$ldap_init;
    call.argc       = 2;
    call.args [ 0 ] = spoof_arg ( HostName );
    call.args [ 1 ] = spoof_arg ( PortNumber );

    return ( LDAP * ) spoof_call ( &call );
}

// WS2_32 and WSOCK32 hooks
int WSAAPI _bind ( SOCKET s, const struct sockaddr * name, int namelen )
{
    FUNCTION_CALL call = { 0 };

    call.ptr        = ( PVOID ) ( WS2_32$bind );
    call.argc       = 3;
    call.args [ 0 ] = spoof_arg ( s );
    call.args [ 1 ] = spoof_arg ( name );
    call.args [ 2 ] = spoof_arg ( namelen );

    return ( int ) spoof_call ( &call );
}

int WSAAPI _send ( SOCKET s, const char * buf, int len, int flags )
{
    FUNCTION_CALL call = { 0 };

    call.ptr        = ( PVOID ) ( WS2_32$send );
    call.argc       = 4;
    call.args [ 0 ] = spoof_arg ( s );
    call.args [ 1 ] = spoof_arg ( buf );
    call.args [ 2 ] = spoof_arg ( len );
    call.args [ 3 ] = spoof_arg ( flags );

    return ( int ) spoof_call ( &call );
}

SOCKET WSAAPI _socket ( int af, int type, int protocol )
{
    FUNCTION_CALL call = { 0 };

    call.ptr        = ( PVOID ) ( WS2_32$socket );
    call.argc       = 3;
    call.args [ 0 ] = spoof_arg ( af );
    call.args [ 1 ] = spoof_arg ( type );
    call.args [ 2 ] = spoof_arg ( protocol );

    return ( SOCKET ) spoof_call ( &call );
}

PLDAPSearch LDAPAPI _ldap_search_init_pageA ( PLDAP ExternalHandle, const PSTR DistinguishedName, ULONG ScopeOfSearch, const PSTR SearchFilter, PZPSTR AttributeList, ULONG AttributesOnly, PLDAPControlA * ServerControls, PLDAPControlA * ClientControls, ULONG PageTimeLimit, ULONG TotalSizeLimit, PLDAPSortKeyA * SortKeys )
{
    FUNCTION_CALL call = { 0 };

    call.ptr         = ( PVOID ) WLDAP32$ldap_search_init_pageA;
    call.argc        = 11;
    call.args [ 0 ]  = spoof_arg ( ExternalHandle );
    call.args [ 1 ]  = spoof_arg ( DistinguishedName );
    call.args [ 2 ]  = spoof_arg ( ScopeOfSearch );
    call.args [ 3 ]  = spoof_arg ( SearchFilter );
    call.args [ 4 ]  = spoof_arg ( AttributeList );
    call.args [ 5 ]  = spoof_arg ( AttributesOnly );
    call.args [ 6 ]  = spoof_arg ( ServerControls );
    call.args [ 7 ]  = spoof_arg ( ClientControls );
    call.args [ 8 ]  = spoof_arg ( PageTimeLimit );
    call.args [ 9 ]  = spoof_arg ( TotalSizeLimit );
    call.args [ 10 ] = spoof_arg ( SortKeys );

    return ( PLDAPSearch ) spoof_call ( &call );
}

BOOL WINAPI _GetTokenInformation ( HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, LPVOID TokenInformation, DWORD TokenInformationLength, PDWORD ReturnLength )
{
    FUNCTION_CALL call = { 0 };

    call.ptr        = ( PVOID ) ADVAPI32$GetTokenInformation;
    call.argc       = 5;
    call.args [ 0 ] = spoof_arg ( TokenHandle );
    call.args [ 1 ] = spoof_arg ( TokenInformationClass );
    call.args [ 2 ] = spoof_arg ( TokenInformation );
    call.args [ 3 ] = spoof_arg ( TokenInformationLength );
    call.args [ 4 ] = spoof_arg ( ReturnLength );

    return ( BOOL ) spoof_call ( &call );
}

BOOL WINAPI _OpenProcessToken ( HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle )
{
    FUNCTION_CALL call = { 0 };

    call.ptr        = ( PVOID ) ADVAPI32$OpenProcessToken;
    call.argc       = 3;
    call.args [ 0 ] = spoof_arg ( ProcessHandle );
    call.args [ 1 ] = spoof_arg ( DesiredAccess );
    call.args [ 2 ] = spoof_arg ( TokenHandle );

    return ( BOOL ) spoof_call ( &call );
}

HANDLE WINAPI _GetCurrentThread ( VOID )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID ) KERNEL32$GetCurrentThread;
    call.argc = 0;

    return ( HANDLE ) spoof_call ( &call );
}

HANDLE WINAPI _GetCurrentProcess ( VOID )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID ) KERNEL32$GetCurrentProcess;
    call.argc = 0;

    return ( HANDLE ) spoof_call ( &call );
}

DWORD WINAPI _WaitForSingleObject ( HANDLE hHandle, DWORD dwMilliseconds )
{
    FUNCTION_CALL call = { 0 };

    call.ptr        = ( PVOID ) KERNEL32$WaitForSingleObject;
    call.argc       = 2;
    call.args [ 0 ] = spoof_arg ( hHandle );
    call.args [ 1 ] = spoof_arg ( dwMilliseconds );

    return ( DWORD ) spoof_call ( &call );
}

// SHELL32 hooks
HINSTANCE WINAPI _ShellExecuteA ( HWND hwnd, LPCSTR lpOperation, LPCSTR lpFile, LPCSTR lpParameters, LPCSTR lpDirectory, INT nShowCmd )
{
    FUNCTION_CALL call = { 0 };

    call.ptr        = ( PVOID ) SHELL32$ShellExecuteA;
    call.argc       = 6;
    call.args [ 0 ] = spoof_arg ( hwnd );
    call.args [ 1 ] = spoof_arg ( lpOperation );
    call.args [ 2 ] = spoof_arg ( lpFile );
    call.args [ 3 ] = spoof_arg ( lpParameters );
    call.args [ 4 ] = spoof_arg ( lpDirectory );
    call.args [ 5 ] = spoof_arg ( nShowCmd );

    return ( HINSTANCE ) spoof_call ( &call );
}

// SECUR32 hooks
NTSTATUS NTAPI _LsaRegisterLogonProcess ( PLSA_STRING LogonProcessName, PHANDLE LsaHandle, PLSA_OPERATIONAL_MODE SecurityMode )
{
    FUNCTION_CALL call = { 0 };

    call.ptr        = ( PVOID ) SECUR32$LsaRegisterLogonProcess;
    call.argc       = 3;
    call.args [ 0 ] = spoof_arg ( LogonProcessName );
    call.args [ 1 ] = spoof_arg ( LsaHandle );
    call.args [ 2 ] = spoof_arg ( SecurityMode );

    return ( NTSTATUS ) spoof_call ( &call );
}

NTSTATUS NTAPI _LsaConnectUntrusted ( PHANDLE LsaHandle )
{
    FUNCTION_CALL call = { 0 };

    call.ptr        = ( PVOID ) SECUR32$LsaConnectUntrusted;
    call.argc       = 1;
    call.args [ 0 ] = spoof_arg ( LsaHandle );

    return ( NTSTATUS ) spoof_call ( &call );
}

// WS2_32 hooks
int WSAAPI _connect ( SOCKET s, const struct sockaddr * name, int namelen )
{
    FUNCTION_CALL call = { 0 };

    call.ptr        = ( PVOID ) ( WS2_32$connect );
    call.argc       = 3;
    call.args [ 0 ] = spoof_arg ( s );
    call.args [ 1 ] = spoof_arg ( name );
    call.args [ 2 ] = spoof_arg ( namelen );

    return ( int ) spoof_call ( &call );
}

int WSAAPI _getaddrinfo ( const char * nodename, const char * servname, const struct addrinfo * hints, struct addrinfo ** res )
{
    FUNCTION_CALL call = { 0 };

    call.ptr        = ( PVOID ) ( WS2_32$getaddrinfo );
    call.argc       = 4;
    call.args [ 0 ] = spoof_arg ( nodename );
    call.args [ 1 ] = spoof_arg ( servname );
    call.args [ 2 ] = spoof_arg ( hints );
    call.args [ 3 ] = spoof_arg ( res );

    return ( int ) spoof_call ( &call );
}
