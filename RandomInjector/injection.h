#include "pch.h"
DWORD GetProcessIdByName(LPCTSTR lpszProcessName);
BOOL EarlyBird(LPVOID lpShellcode,DWORD dwSize);
BOOL EarlyBird2(LPVOID lpAddress, DWORD dwSize);
BOOL ClassicInjection(LPVOID lpAddress, DWORD dwSize);
BOOL ThreadHijack(LPVOID lpAddress, DWORD dwSize);