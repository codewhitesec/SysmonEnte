#include <windows.h>
#include <stdio.h>
#include <aclapi.h>
#include <tlhelp32.h>

DWORD GetSysmonPid(wchar_t sysmonname[]);
BOOL SetPrivilege(LPWSTR lpwPriv);
BOOL IsElevated();


#define FAIL 0
#define SUCCESS 1

DWORD main() {

    DWORD dwSuccess = FAIL;
    DWORD dwPid = 0;
    HANDLE hProcess = NULL;

    //Changeme if you want the SACL for a different process name
    wchar_t wstr_sysmon[] = L"Sysmon64.exe";

    //Enable object access auditing on PROCESS_VM_OPERATION | PROCESS_DUP_HANDLE | ACCESS_SYSTEM_SECURITY for success
    ACCESS_MASK am_saclpermissions = PROCESS_VM_OPERATION | PROCESS_DUP_HANDLE | ACCESS_SYSTEM_SECURITY;

    EXPLICIT_ACCESS ea[1];
    SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;
    
    PSID pEveryoneSID = NULL;
    PACL pACL = NULL;
    SE_OBJECT_TYPE objecttype = SE_KERNEL_OBJECT;
    SECURITY_INFORMATION securityInformation = SACL_SECURITY_INFORMATION;
    PISECURITY_DESCRIPTOR pSD = NULL;

    if (!IsElevated()) {
        dwSuccess = FAIL;
        printf("- You need elevated rights to set the SACL for Sysmon\n");
        goto exit;
    }

    //Set the rights that are neeeded to set up the SACL
    //SeSecurity seems not to be required at least on win11
    
    SetPrivilege((LPWSTR)L"SeDebugPrivilege");
    SetPrivilege((LPWSTR)L"SeSecurityPrivilege");
  
    dwPid = GetSysmonPid(wstr_sysmon);
    if (dwPid == 0) {
        dwSuccess = FAIL;
        printf("- Could not get Sysmon PID, maybe you have a different Process Name or Sysmon is not running\n");
        goto exit;
    }
    printf("+ Sysmon pid: %d\n", dwPid);
    
    
    //ACCESS_SYSTEM_SECURITY is required to set the SACL
    hProcess = OpenProcess(ACCESS_SYSTEM_SECURITY, FALSE, dwPid);
    if (hProcess == NULL) {
        dwSuccess = FAIL;
        printf("Could not open the Sysmon Process with the right to set the SACL\n");
        goto exit;
    }

    

    if (!AllocateAndInitializeSid(&SIDAuthWorld, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &pEveryoneSID)) {
        dwSuccess = FAIL;
        printf("- Could not Initialize SID Everyone\n");
        goto exit;
    }

    //Setting SACL Audit Success
    ZeroMemory(&ea,sizeof(EXPLICIT_ACCESS));
    ea[0].grfAccessPermissions = am_saclpermissions;
    ea[0].grfAccessMode = SET_AUDIT_SUCCESS;
    ea[0].grfInheritance = NO_INHERITANCE;
    ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea[0].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea[0].Trustee.ptstrName = (LPTSTR)pEveryoneSID;


    dwSuccess = SetEntriesInAcl(1, ea, NULL, &pACL);
    if (ERROR_SUCCESS != dwSuccess){
        printf("- Could not setup ACL\n");
        dwSuccess = FAIL;
        goto exit;
    }
    
    
    dwSuccess = SetSecurityInfo(hProcess, objecttype, securityInformation, NULL, NULL, NULL, pACL);
    if (dwSuccess == 0) {
        printf("+ Successfully set the new SACL :)\n");
        dwSuccess = SUCCESS;
    }
    else {
        printf("- Could not set the SACL :(\n");
        dwSuccess = FAIL;
        goto exit;
    }
    
    
exit:
    if (hProcess)
        CloseHandle(hProcess);
    
    return dwSuccess;

}