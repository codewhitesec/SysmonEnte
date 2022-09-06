#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

//Get PID of process, return first occurence of the process name
DWORD GetSysmonPid(wchar_t wstr_sysmon[]) {
    DWORD dwPid = 0;

    HANDLE hProcessSnap = NULL;
    PROCESSENTRY32 pe32 = { 0x00 };


    printf("Trying to get the pid of: %ls\n", wstr_sysmon);

    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hProcessSnap == INVALID_HANDLE_VALUE)
    {
        goto exit;
    }
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hProcessSnap, &pe32))
    {
        goto exit;
    }

    do {
        if (0 == lstrcmpW(wstr_sysmon, pe32.szExeFile)) {
            dwPid = pe32.th32ProcessID;
            break;
        }

    } while (Process32Next(hProcessSnap, &pe32));


exit:
    return dwPid;
}