#include "pch.h"
DWORD GetProcessIdByName(LPCTSTR lpszProcessName);
BOOL EarlyBird(LPVOID lpShellcode,DWORD dwSize);
BOOL EarlyBird2(LPVOID lpAddress, DWORD dwSize);
BOOL ClassicInjection(LPVOID lpAddress, DWORD dwSize);
BOOL ThreadHijack(LPVOID lpAddress, DWORD dwSize);
BOOL NtMapInjection(LPVOID lpAddress, DWORD dwSize);
BOOL MapingInjection(LPVOID lpAddress, DWORD dwSize);
BOOL Session0Injection(LPVOID lpAddress, DWORD dwSize);

#ifdef _WIN64
typedef DWORD(WINAPI* typedef_ZwCreateThreadEx)(
	PHANDLE ThreadHandle,
	ACCESS_MASK DesiredAccess,
	LPVOID ObjectAttributes,
	HANDLE ProcessHandle,
	LPTHREAD_START_ROUTINE lpStartAddress,
	LPVOID lpParameter,
	ULONG CreateThreadFlags,
	SIZE_T ZeroBits,
	SIZE_T StackSize,
	SIZE_T MaximumStackSize,
	LPVOID pUnkown);
#else
typedef DWORD(WINAPI* typedef_ZwCreateThreadEx)(
	PHANDLE ThreadHandle,
	ACCESS_MASK DesiredAccess,
	LPVOID ObjectAttributes,
	HANDLE ProcessHandle,
	LPTHREAD_START_ROUTINE lpStartAddress,
	LPVOID lpParameter,
	BOOL CreateSuspended,
	DWORD dwStackSize,
	DWORD dw1,
	DWORD dw2,
	LPVOID pUnkown);
#endif