#include <stdio.h>
#include "windows.h"

#include "SysmonEnte.h"

void help(wchar_t**);

int wmain( int argc, wchar_t *argv[], wchar_t *envp[] ) {
    
    DWORD dwPid = 0;
    BOOL bSuccess = FALSE;

    if(argc < 2)
      help(argv);

    dwPid = _wtoi(argv[1]);

    bSuccess = ( ( GO* )SysmonEnte )( dwPid );
    if(bSuccess == FALSE){
      wprintf(L"- SysmonEnte Failed!: %d\n", bSuccess);
    } else {
      wprintf(L"+ SysmonEnte Succeeded!: %d\n", bSuccess);
    }

    

    return 0;

}

void
help(wchar_t** argv) {

    wprintf(L"%ls <Sysmon PID>\n", argv[0]);
    exit(0);

}
