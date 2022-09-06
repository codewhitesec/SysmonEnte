#include "threads.h"

BOOL SuspendResumeThreads(PAPI pApi, DWORD dwPid) {

	BOOL bSuccess = FALSE, bContinue = TRUE;
	NTSTATUS status;
	PVOID pBuffer = NULL;
	ULONG uBufferSize = 0;
	HANDLE hThread = NULL;

	_PSYSTEM_PROCESS_INFORMATION pProcessInformation = NULL;
	_SYSTEM_THREAD_INFORMATION threadInformation = { 0x00 };
	OBJECT_ATTRIBUTES ObjectAttributes;
	InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);

	do {

		PrepareSyscall(pApi->Nt.NtQuerySystemInformation.dwSyscallNr, pApi->Nt.NtQuerySystemInformation.pRecycledGate);
		status = DoSyscall((SYSTEM_INFORMATION_CLASS)5, pBuffer, uBufferSize, &uBufferSize);

		if (!NT_SUCCESS(status)) {
			if (status == STATUS_INFO_LENGTH_MISMATCH){
					if (pBuffer != NULL)
						pApi->Kernel32.VirtualFree(pBuffer, 0, MEM_RELEASE);
				pBuffer = pApi->Kernel32.VirtualAlloc(NULL, uBufferSize, MEM_COMMIT, PAGE_READWRITE);
				continue;
			}
			break;
		}

		else {
			pProcessInformation = (_PSYSTEM_PROCESS_INFORMATION)pBuffer;
			break;
		}

	} while (1);

	while (pProcessInformation && pProcessInformation->NextEntryOffset && bContinue) {
		
		if (pProcessInformation->ProcessId == dwPid) {

			for (ULONG i = 0; i < pProcessInformation->NumberOfThreads; i++) {

				threadInformation = pProcessInformation->ThreadInfos[i];

				PrepareSyscall(pApi->Nt.NtOpenThread.dwSyscallNr, pApi->Nt.NtOpenThread.pRecycledGate);
				status = DoSyscall(&hThread, THREAD_ALL_ACCESS, &ObjectAttributes, threadInformation.ClientId);
				if (!NT_SUCCESS(status) || hThread == NULL)
					break;

				if (threadInformation.WaitReason == Suspended) {

					PrepareSyscall(pApi->Nt.NtResumeThread.dwSyscallNr, pApi->Nt.NtResumeThread.pRecycledGate);
					status = DoSyscall(hThread, NULL);
					if (!NT_SUCCESS(status))
						break;

				} else {

					PrepareSyscall(pApi->Nt.NtSuspendThread.dwSyscallNr, pApi->Nt.NtSuspendThread.pRecycledGate);
					status = DoSyscall(hThread, NULL);
					if (!NT_SUCCESS(status))
						break;

				}

				if (hThread)
					pApi->Kernel32.CloseHandle(hThread);

			}

			bContinue = FALSE;
		}

		pProcessInformation = (_PSYSTEM_PROCESS_INFORMATION)((LPBYTE)pProcessInformation + pProcessInformation->NextEntryOffset);

	}

	bSuccess = TRUE;

	if (pBuffer)
		pApi->Kernel32.VirtualFree(pBuffer, 0, MEM_RELEASE);

	return bSuccess;

}